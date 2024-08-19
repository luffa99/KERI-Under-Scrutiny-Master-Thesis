mod helpers;
use std::{fs, io::BufReader, process::exit, time::Duration, vec};
use acdc::attributes::InlineAttributes;
use async_std::task::sleep;
use helpers::helpers::{
    get_current_formatted_datetime, is_port_open, parse_watcher_config_oobi, parse_witness_config_oobi, serialize_json_and_write, KeriController, MessageWithSignatureAndEventSeal
};
use keri_controller::{LocationScheme, Oobi};
use colored::Colorize;
use indicatif::ProgressBar;
use reqwest::header::{HeaderMap, HeaderValue, CONTENT_TYPE};

#[tokio::main(flavor = "multi_thread")]
async fn main() {
    println!("");

    let usage = "Usage: <# Witnesses> <Witness Threeshold> <# Watchers> <experiment>";

    let m_witnesses : usize = std::env::args().nth(1).expect(&usage).parse().unwrap();
    let witness_threeshold : u64 = std::env::args().nth(2).expect(&usage).parse().unwrap();
    let m_watchers : usize = std::env::args().nth(3).expect(&usage).parse().unwrap();
    let experiment : String = std::env::args().nth(4).expect(&usage).parse().unwrap();

    // SETUP NETWORK WITNESSES
    // Vectors containing Identifiers and OOBI of witnesses
    let mut ch_gov_wit_net_oobi: Vec<Oobi> = vec![];

    // Parse the witness config from the file `config/witnessConfig.json`
    // Assume witnesses are setup by the botmaster
    parse_witness_config_oobi(&mut ch_gov_wit_net_oobi);

    // Check that all witnesses are reachable
    for vv in ch_gov_wit_net_oobi.clone() {
        let v : LocationScheme = match vv {
            Oobi::Location(ls) => ls,
            _ => panic!("Error in unwrapping Witness Oobi")
        };
        if !is_port_open(v.get_url().host_str().unwrap().to_string(), v.get_url().port().unwrap()) {
            println!("{} Witness {} is not reachable", "Error:".red(), v.get_url().as_str().red());
        }
    }

    // SETUP NETWORK WATCHERS
    // Vectors containing Identifiers and OOBI of watchers
    let mut ch_gov_wat_net_oobi: Vec<Oobi> = vec![];
    // Parse the witness config from the file `config/watcherConfigs.json`
    parse_watcher_config_oobi(&mut ch_gov_wat_net_oobi);

    // Check that all witnesses are reachable
    for vv in ch_gov_wat_net_oobi.clone() {
        let v : Option<LocationScheme> = match vv {
            Oobi::Location(ls) => Some(ls),
            _ => None
        };
        if !is_port_open(v.clone().unwrap().get_url().host_str().unwrap().to_string(), 
                        v.clone().unwrap().get_url().port().unwrap()) 
        {
            println!("{} Watcher {} is not reachable", "Error:".red(), v.unwrap().get_url().as_str().red());
        }
    }

    // Input values sanity check
    if m_witnesses < 1 || m_witnesses > ch_gov_wit_net_oobi.len() {
        panic!("Invalid value for <# Witnesses>. Your input: {}, but value must be in range [1,{}]", m_witnesses, ch_gov_wit_net_oobi.len());
    }
    if witness_threeshold < 1 || witness_threeshold > m_witnesses.try_into().unwrap() {
        panic!("Invalid value for <Witness Threeshold>. Your input: {}, but value must be in range [1,{}]", witness_threeshold, m_witnesses);
    }
    if m_watchers < 1 || m_watchers > ch_gov_wat_net_oobi.len() {
        panic!("Invalid value for <# Watchers>. Your input: {}, but value must be in range [1,{}]", m_watchers, ch_gov_wat_net_oobi.len());
    }

    // GET IPS OF NODES
    let mut nodes_ips : Vec<String> = parse_nodes_configs();

    // SETUP HTTP CLIENT
    let client = reqwest::Client::new();

    // Init Issuer
    let mut issuer = KeriController::incept(
        "Issuer_1".to_string(), 
        KeriController::pick_m_random_oobi(ch_gov_wit_net_oobi, m_witnesses), 
        KeriController::pick_m_random_oobi(ch_gov_wat_net_oobi, m_watchers), 
        witness_threeshold, 
        vec![], 
        true
    ).await.unwrap();

    // Sign message with established identifier
    let msg: String = "Hi, I'm the Issuer :)".to_string();
    let message_1: MessageWithSignatureAndEventSeal = issuer.sign_message(msg.clone()).await.unwrap();

    println!("Starting TEST 1+2");
    println!("Sending message");
    let mut timings : Vec<String> = vec![];
    timings.push(get_current_formatted_datetime());

    // Send to all the load nodes => they will start test1
    for ip in nodes_ips.clone() {
        let mut trials = 3;
        while trials > 0 {
            // println!("User {} ... ", ip.clone());
            let res = client.post(ip.clone())
                .json(&message_1)
                .timeout(Duration::from_secs(3))
                .send()
                .await;
            match res {
                Ok(res_ok) => {/*println!("{:?}", res_ok.status());*/ break},
                Err(err) => println!("{} {:?}", "Timeout:".red(), err),
            }
            trials -= 1;
        }
    }

    // Do the rotation
    println!("Waiting 300 seconds");
    wait_notifications_or_timeout(300, experiment.clone(), "count2".to_string(), nodes_ips.clone()).await;

    println!("Waiting 5 seconds");
    let bar = ProgressBar::new(5);
    for _ in 0..5 {
        sleep(Duration::from_secs(1)).await;
        bar.inc(1);
    }
    bar.finish();

    println!("Starting TEST 3");
    timings.push(get_current_formatted_datetime());
    issuer.rotate(1, witness_threeshold, vec![], vec![]).await.unwrap();

    // Sign message with rotated keys.  
    let message_2 = issuer.sign_message(msg).await.unwrap();

    println!("Send message...");
    timings.push(get_current_formatted_datetime());

    // send to all the load nodes to start test 3
    let mut test_3_fails = 0;
    for ip in nodes_ips.clone() {
        let mut trials = 3;
        let mut is_success = false;
        while trials > 0 {
            // println!("User {} ... ", ip.clone());
            let res = client.post(ip.clone())
                .json(&message_2)
                .timeout(Duration::from_secs(3))
                .send()
                .await;
            match res {
                Ok(res_ok) => {/*println!("{:?}", res_ok.status());*/ is_success = true; break},
                Err(err) => {println!("{} {:?}", "Timeout:".red(), err); sleep(Duration::from_secs(1)).await;},
            }
            trials -= 1;
        }
        if !is_success {
            test_3_fails += 1;
            nodes_ips.retain(|x| *x != ip);
        }
        if test_3_fails > nodes_ips.len() / 3 {
            exit(1);
        }
    }


    wait_notifications_or_timeout(300, experiment.clone(), "count3".to_string(), nodes_ips.clone()).await;
    println!("Waiting 5 seconds");
    let bar = ProgressBar::new(5);
    for _ in 0..5 {
        sleep(Duration::from_secs(1)).await;
        bar.inc(1);
    }
    bar.finish();

    println!("Starting TEST 4");
    println!("Skipped--");
    // timings.push(get_current_formatted_datetime());
    // // Creating TEL and ACDC Credential
    // issuer.incept_tel().await.unwrap();
    // let mut acdc_attributes = InlineAttributes::default();
    //     acdc_attributes.insert("name".to_string(), "Sample Helvetia".into());
    //     acdc_attributes.insert("birthdate".to_string(), "01.01.2000".into());
    //     acdc_attributes.insert("eID".to_string(), "A00A00B".into());
    // let mut acdc = issuer.issue_private_acdc(acdc_attributes, None).await.unwrap();
    // let message_3 = acdc.clone();
    // // send to all the load nodes to start test 4
    // let mut test_4_fails = 0;
    // for ip in nodes_ips.clone() {
    //     let mut trials = 3;
    //     let mut is_success = false;
    //     while trials > 0 {
    //         // println!("User {} ... ", ip.clone());
    //         let res = client.post(ip.clone())
    //             .json(&message_3)
    //             .timeout(Duration::from_secs(3))
    //             .send()
    //             .await;
    //         match res {
    //             Ok(res_ok) => {/*println!("{:?}", res_ok.status());*/ is_success = true; break},
    //             Err(err) => {println!("{} {:?}", "Timeout:".red(), err); sleep(Duration::from_secs(1)).await;},
    //         }
    //         trials -= 1;
    //     }
    //     if !is_success {
    //         test_4_fails += 1;
    //         nodes_ips.retain(|x| *x != ip);
    //     }
    //     if test_4_fails > nodes_ips.len() / 3 {
    //         exit(1);
    //     }
    // }


    // wait_notifications_or_timeout(300, experiment.clone(),"count4".to_string(), nodes_ips.clone()).await;
    // Skipping test
    // println!("Waiting 15 seconds");
    // let bar = ProgressBar::new(15);
    // for _ in 0..15 {
    //     sleep(Duration::from_secs(1)).await;
    //     bar.inc(1);
    // }
    // bar.finish();

    println!("Starting TEST 5");
    println!("skipped--");
    // timings.push(get_current_formatted_datetime());
    // // Revoking credential
    // // issuer.revoke
    // println!("{:?}", acdc.event_seal);
    // issuer.revoke_acdc(&mut acdc).await.unwrap();
    // println!("{:?}", acdc.event_seal);

    // // send to all the load nodes to start test 5
    // let mut test_5_fails = 0;
    // for ip in nodes_ips.clone() {
    //     let mut trials = 3;
    //     let mut is_success = false;
    //     while trials > 0 {
    //         // println!("User {} ... ", ip.clone());
    //         let res = client.post(ip.clone())
    //             .json(&acdc.clone())
    //             .timeout(Duration::from_secs(3))
    //             .send()
    //             .await;
    //         match res {
    //             Ok(res_ok) => {/*println!("{:?}", res_ok.status());*/ is_success = true; break},
    //             Err(err) => {println!("{} {:?}", "Timeout:".red(), err); sleep(Duration::from_secs(1)).await;},
    //         }
    //         trials -= 1;
    //     }
    //     if !is_success {
    //         test_5_fails += 1;
    //         nodes_ips.retain(|x| *x != ip);
    //     }
    //     if test_5_fails > nodes_ips.len() / 3 {
    //         exit(1);
    //     }
    // }


    // wait_notifications_or_timeout(300, experiment.clone(),"count5".to_string(), nodes_ips.clone()).await;
    // Skipping
    // println!("Waiting 15 seconds");
    // let bar = ProgressBar::new(15);
    // for _ in 0..15 {
    //     sleep(Duration::from_secs(1)).await;
    //     bar.inc(1);
    // }
    // bar.finish();

    println!("Starting TEST 6");
    timings.push(get_current_formatted_datetime());
    // Let everyone rotate!!

    // send to all the load nodes
    for ip in nodes_ips.clone() {
        let mut trials = 3;
        while trials > 0 {
            // println!("User {} ... ", ip.clone());
            let res = client.post(ip.clone())
                .json(&"START_ROTATION") // Sending a string
                .timeout(Duration::from_secs(3))
                .send()
                .await;
            match res {
                Ok(res_ok) => {/*println!("{:?}", res_ok.status());*/ break},
                Err(err) => {println!("{} {:?}", "Timeout:".red(), err); sleep(Duration::from_secs(1)).await;},
            }
            trials -= 1;
        }
    }

    serialize_json_and_write(timings, "issuer_timings.json".to_string());
}

fn parse_nodes_configs() -> Vec<String> {
    let file = fs::File::open("config/nodesConfigs.json")
        .expect("Cannot open `config/nodesConfigs.json`");
    let reader = BufReader::new(file);

    let json : Vec<String> = serde_json::from_reader(reader).unwrap();

    return json
}

async fn wait_notifications_or_timeout(
    timeout: u64, 
    experiment_name: String, 
    test_name: String, 
    nodes_ips: Vec<String>) 
{
    let bar = ProgressBar::new(timeout);
    for _ in 0..timeout {
        sleep(Duration::from_secs(1)).await;
        bar.inc(1);

        let url = "https://dev1.rail-suisse.ch/keri/SL9iQPv3eoQctEsqqTtobysmGJCeVAJRSBn8fAO5HVThkombleK6UoxZjHPEtFqP/get.php";
        let mut headers = HeaderMap::new();
        headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/x-www-form-urlencoded"));
        let params = [("experiment", experiment_name.clone()), ("count", test_name.clone())];
        let data = serde_urlencoded::to_string(&params).unwrap();
        let client = reqwest::Client::new();
        let resp = client.post(url)
            .headers(headers)
            .body(data)
            .send()
            .await;
        match resp {
            Ok(response) => {
                if response.status() != reqwest::StatusCode::OK {
                    println!("Error: server");
                } else if response.text().await.unwrap_or("0".to_string()).parse().unwrap_or(0) >= nodes_ips.len() {
                    println!("All users done. Continue.");
                    break;
                }
            },
            Err(_) => {
                println!("Error: server");
            }
        }
    }
    bar.finish();
}