mod helpers;
use std::{borrow::Borrow, error::Error, future::Future, panic, process::exit, sync::Arc, time::Duration};

use helpers::helpers::{
    ask_watchers_to_watch_identifiers, clear_data, init_identifier, init_identifier_with_watcher, init_tel, issue_private_acdc, p_id, query_kel, serialize_json_and_write, start_watcher, start_witness, verify_credential, KeriController, MessageWithSignatureAndEventSeal, ToWatch
};
use keri_controller::{controller::Controller, identifier::Identifier, BasicPrefix, CryptoBox, IdentifierPrefix, KeyManager, LocationScheme, Oobi, SelfSigningPrefix, TelState};
use keri_core::{event::sections::seal::EventSeal, event_message::signature::Signature, processor::validator::{MoreInfoError, VerificationError}};
use openssl::hash::MessageDigest;
use rand::Rng;
use reqwest::header::{HeaderMap, HeaderValue, CONTENT_TYPE};
use said::{derivation::{HashFunction, HashFunctionCode}, sad::{SerializationFormats, SAD}, version::Encode};
use serde_json::json;
use tokio::{sync::{broadcast::{self, Receiver}, Barrier, Mutex}, task::JoinSet, time::{sleep, Instant}};
use std::net::{TcpStream, SocketAddr};
use colored::Colorize;
use acdc::{attributes::InlineAttributes, Attestation};

#[tokio::main(flavor = "multi_thread")]
async fn main() {
    println!("");

    let n_users : i32 = std::env::args().nth(1).expect("Missing number of user parameter (int)").parse().unwrap_or(10);
    println!("Number of users: {}", n_users);

    let start_infra : bool = std::env::args().nth(2).expect("Missing starting infrastructure").parse().unwrap_or(true);
    let mut prefix : String = "localhost".to_string();

    if start_infra {
        println!("Starting DEMO infrastructure (6 Witnesses + 6 Watchers)");

        clear_data();

        // Init Witnesses and Watchers Network
        let show_wit_wat_debug = false;
        start_witness("CH_wit_01_dev.yml", show_wit_wat_debug); //4043 BHWp2RC0DcASYNWix4ln8LMaTmsJLlEEDGodGFdk3DsK
        start_witness("CH_wit_02_dev.yml", show_wit_wat_debug); //4044 BKi9A_efzy5tQv8OEuo-zSHamigGmQ6PW147KsspLATe
        start_witness("CH_wit_03_dev.yml", show_wit_wat_debug); //4045 BH5lwtC7sNefgsiUOYnlkiZ31vTirx5aiwB_CfdBWYB3
        start_witness("CH_wit_04_dev.yml", show_wit_wat_debug); //4046 BFvE03fcIi1WpCJFasELVUeJKKK1Aj0hw261LJhMYrWX
        start_witness("CH_wit_05_dev.yml", show_wit_wat_debug); //4047 BFg6ehxH_iyYleiApcBj3u1DgSPo8PQuzi4SBCn8BnIL
        start_witness("CH_wit_06_dev.yml", show_wit_wat_debug); //4048 BAo3EIXNe02xsxnAM4SgWKNixeybKDjP-c2u1P9e3QO0

        start_watcher("CH_wat_01_dev.yml", show_wit_wat_debug); //4052 BAdD110n6VADC-cfly0XBVYCJIzGLmXuKtlPcv0QnN27
        start_watcher("CH_wat_02_dev.yml", show_wit_wat_debug); //4053 BBGPx73VMXqwAVWFNTO9usZ8ifsZNDUtisyKGbXIB-Un
        start_watcher("CH_wat_03_dev.yml", show_wit_wat_debug); //4054 BLFroicVvduhIlVVMVHfzim_aGFpIMrHiRXJQkMsYIO5
        start_watcher("CH_wat_04_dev.yml", show_wit_wat_debug); //4055 BITbtqfH1NIJm5t9OlihYnYmol0J2bJqL2uZFotLLD4K
        start_watcher("CH_wat_05_dev.yml", show_wit_wat_debug); //4056 BMuN2u-Oco7bfe1UWI9wVKEi-9zXWyzz6DxsVwldLcYn
        start_watcher("CH_wat_06_dev.yml", show_wit_wat_debug); //4057 BOeNt92oyTaITqnY1XgXxse98PILgPhsYlCJdsSqweGI

        println!("Waiting for infrastructure to start...");
        sleep(Duration::from_millis(3000)).await;

    } else {
        prefix = std::env::args().nth(3).expect("Missing address");
    }

    assert!(is_port_open(prefix.clone(), 4043));

    let ch_wit_01_id: BasicPrefix = "BHWp2RC0DcASYNWix4ln8LMaTmsJLlEEDGodGFdk3DsK".parse().unwrap();
    let ch_wit_01_oobi: LocationScheme = serde_json::from_str(&format!(
        r#"{{"eid":{:?},"scheme":"http","url":"http://{}:4043/"}}"#, ch_wit_01_id, prefix
    )).unwrap();
    let ch_wit_02_id: BasicPrefix = "BKi9A_efzy5tQv8OEuo-zSHamigGmQ6PW147KsspLATe".parse().unwrap();
    let ch_wit_02_oobi: LocationScheme = serde_json::from_str(&format!(
        r#"{{"eid":{:?},"scheme":"http","url":"http://{}:4044/"}}"#, ch_wit_02_id, prefix
    )).unwrap();
    let ch_wit_03_id: BasicPrefix = "BH5lwtC7sNefgsiUOYnlkiZ31vTirx5aiwB_CfdBWYB3".parse().unwrap();
    let ch_wit_03_oobi: LocationScheme = serde_json::from_str(&format!(
        r#"{{"eid":{:?},"scheme":"http","url":"http://{}:4045/"}}"#, ch_wit_03_id, prefix
    )).unwrap();
    let ch_wit_04_id: BasicPrefix = "BFvE03fcIi1WpCJFasELVUeJKKK1Aj0hw261LJhMYrWX".parse().unwrap();
    let ch_wit_04_oobi: LocationScheme = serde_json::from_str(&format!(
        r#"{{"eid":{:?},"scheme":"http","url":"http://{}:4046/"}}"#, ch_wit_04_id, prefix
    )).unwrap();
    let ch_wit_05_id: BasicPrefix = "BFg6ehxH_iyYleiApcBj3u1DgSPo8PQuzi4SBCn8BnIL".parse().unwrap();
    let ch_wit_05_oobi: LocationScheme = serde_json::from_str(&format!(
        r#"{{"eid":{:?},"scheme":"http","url":"http://{}:4047/"}}"#, ch_wit_05_id, prefix
    )).unwrap();
    let ch_wit_06_id: BasicPrefix = "BAo3EIXNe02xsxnAM4SgWKNixeybKDjP-c2u1P9e3QO0".parse().unwrap();
    let ch_wit_06_oobi: LocationScheme = serde_json::from_str(&format!(
        r#"{{"eid":{:?},"scheme":"http","url":"http://{}:4048/"}}"#, ch_wit_06_id, prefix
    )).unwrap();

    // Watchers

    let ch_wat_01_id: IdentifierPrefix = "BAdD110n6VADC-cfly0XBVYCJIzGLmXuKtlPcv0QnN27".parse().unwrap();
    let ch_wat_01_oobi: Oobi = serde_json::from_str(&format!(
        r#"{{"eid":"{}","scheme":"http","url":"http://{}:4052/"}}"#, ch_wat_01_id, prefix
    )).unwrap();
    let ch_wat_02_id: IdentifierPrefix = "BBGPx73VMXqwAVWFNTO9usZ8ifsZNDUtisyKGbXIB-Un".parse().unwrap();
    let ch_wat_02_oobi: Oobi = serde_json::from_str(&format!(
        r#"{{"eid":"{}","scheme":"http","url":"http://{}:4053/"}}"#, ch_wat_02_id, prefix
    )).unwrap();
    let ch_wat_03_id: IdentifierPrefix = "BLFroicVvduhIlVVMVHfzim_aGFpIMrHiRXJQkMsYIO5".parse().unwrap();
    let ch_wat_03_oobi: Oobi = serde_json::from_str(&format!(
        r#"{{"eid":"{}","scheme":"http","url":"http://{}:4054/"}}"#, ch_wat_03_id, prefix
    )).unwrap();
    let ch_wat_04_id: IdentifierPrefix = "BITbtqfH1NIJm5t9OlihYnYmol0J2bJqL2uZFotLLD4K".parse().unwrap();
    let ch_wat_04_oobi: Oobi = serde_json::from_str(&format!(
        r#"{{"eid":"{}","scheme":"http","url":"http://{}:4055/"}}"#, ch_wat_04_id, prefix
    )).unwrap();
    let ch_wat_05_id: IdentifierPrefix = "BMuN2u-Oco7bfe1UWI9wVKEi-9zXWyzz6DxsVwldLcYn".parse().unwrap();
    let ch_wat_05_oobi: Oobi = serde_json::from_str(&format!(
        r#"{{"eid":"{}","scheme":"http","url":"http://{}:4056/"}}"#, ch_wat_05_id, prefix
    )).unwrap();
    let ch_wat_06_id: IdentifierPrefix = "BOeNt92oyTaITqnY1XgXxse98PILgPhsYlCJdsSqweGI".parse().unwrap();
    let ch_wat_06_oobi: Oobi = serde_json::from_str(&format!(
        r#"{{"eid":"{}","scheme":"http","url":"http://{}:4057/"}}"#, ch_wat_06_id, prefix
    )).unwrap();

    let ch_gov_wit_net_id: Vec<BasicPrefix> = vec![ch_wit_01_id, ch_wit_02_id, ch_wit_03_id, ch_wit_04_id, ch_wit_05_id, ch_wit_06_id];
    let ch_gov_wit_net_oobi_real: Vec<Oobi> = vec![Oobi::Location(ch_wit_01_oobi), Oobi::Location(ch_wit_02_oobi), Oobi::Location(ch_wit_03_oobi), Oobi::Location(ch_wit_04_oobi), Oobi::Location(ch_wit_05_oobi), Oobi::Location(ch_wit_06_oobi), ];

    // serialize_json_and_write(ch_gov_wit_net_oobi.clone(), "all_witnesses.json".to_string());

    let ch_gov_wat_net_id = vec![ch_wat_01_id, ch_wat_02_id, ch_wat_03_id, ch_wat_04_id, ch_wat_05_id, ch_wat_06_id];
    let ch_gov_wat_net_oobi = vec![ch_wat_01_oobi, ch_wat_02_oobi, ch_wat_03_oobi, ch_wat_04_oobi, ch_wat_05_oobi, ch_wat_06_oobi];

    // Init many roles on KERI
    let mut issuer = KeriController::incept("Issuer_1".to_string(), 
                                                            ch_gov_wit_net_oobi_real.clone(), 
                                                            ch_gov_wat_net_oobi.clone(),
                                                            1,
                                                            vec![],
                                                            true
                                                        ).await.unwrap();
    
    let message = "Hi, I'm the Issuer :)".to_string();
    let first_message = issuer.sign_message(message).await.unwrap();

    let mut futures = JoinSet::new();
    let mut tasks = Vec::new();
    let barrier = Arc::new(Barrier::new(n_users as usize + 1));
    let barrier2 = Arc::new(Barrier::new(n_users as usize + 1));
    let (tx, _rx1) = broadcast::channel::<SignatureWithEventSeal>(144);

    println!("Preparing Data...");

    for n in 0..n_users {
        let wait_future = send_query_kel(barrier.clone(), barrier2.clone(), tx.subscribe(),
                                                                    ch_gov_wit_net_id.clone(),  ch_gov_wit_net_oobi_real.clone(), 
                                                                    ch_gov_wat_net_id.clone(), ch_gov_wat_net_oobi.clone(), 
                                                                    issuer.core.clone(), 
                                                                    n, first_message.clone());
        tasks.push(wait_future);
    }

    println!("Data is ready, starting users");
    let start_time_users_inception = Instant::now();
    for task in tasks {
        futures.spawn(task); 
        let random_delay_ms = rand::thread_rng().gen_range(0..=200);
        sleep(Duration::from_millis(random_delay_ms)).await;
    }

    barrier.wait().await;
    barrier2.wait().await;

    // // Do the rotation
    issuer.rotate(1, 1, vec![], vec![]).await.unwrap();

    // // Querying witnesses to get receipts
    let issuer_id = issuer.core.lock().await.id().clone();
    let second_message = issuer.sign_message("Hi, I'm the Issuer :)".to_string()).await.unwrap();

    // Broadcast second_signature
    tx.send(SignatureWithEventSeal { signature: second_message.signature, event_seal: second_message.event_seal.clone() }).unwrap();


    let end_time_users_inception = Instant::now();

    // Check execution result

    let mut success = 0;
    let mut fail = 0;
    while let Some(succ) = futures.join_next().await {
        if succ.unwrap_or(false) {
            success += 1;
        } else {
            fail += 1;
        }
    };

    let end_time_users_kel = Instant::now();
    let tot_time_inception = end_time_users_inception.duration_since(start_time_users_inception);
    let tot_time_kel = end_time_users_kel.duration_since(end_time_users_inception);

    // #########################################################################################################################################33
    // Issue a credential with a TEL
    // #########################################################################################################################################33

    // First, we have to create a TEL

    issuer.incept_tel().await.unwrap();

    // Issuing an ACDC credential
    let mut acdc_attributes = InlineAttributes::default();
        acdc_attributes.insert("name".to_string(), "Sample Helvetia".into());
        acdc_attributes.insert("birthdate".to_string(), "01.01.2000".into());
        acdc_attributes.insert("eID".to_string(), "A00A00B".into());

    let holder = KeriController::incept("Holder_1".to_string(), 
                                                                            ch_gov_wit_net_oobi_real.clone(), 
                                                                            ch_gov_wat_net_oobi.clone(), 
                                                                            1, 
                                                                            vec![ToWatch {
                                                                                prefix: issuer_id.clone(), 
                                                                                event_seal: issuer.core.lock().await.get_last_establishment_event_seal().unwrap()
                                                                            }], 
                                                                            true).await.unwrap();

    println!("Issue");
    let acdc_credential = issuer.issue_private_acdc(
        acdc_attributes, 
        Some(holder.core.lock().await.id().clone())
    ).await.unwrap();


    let vc_state = holder.verify_credential(acdc_credential).await.unwrap();

    println!("State: {:?}", vc_state);
    assert!(matches!(vc_state, Some(TelState::Issued(_))));

    println!("Executed {} users / {} success / {} fail", n_users, success, fail);
    println!("Inception executed in: {:?} ({:?} p.u.)", tot_time_inception, tot_time_inception / n_users.try_into().unwrap());
    println!("KEL executed in: {:?} ({:?} p.u.)", tot_time_kel, tot_time_kel / n_users.try_into().unwrap());

}

#[derive(Clone)]
#[derive(Debug)]
struct SignatureWithEventSeal {
    signature: Signature,
    event_seal: EventSeal
}

async fn send_query_kel(barrier : Arc<Barrier>, barrier2 : Arc<Barrier>, mut second_signature : broadcast::Receiver<SignatureWithEventSeal>,
    ch_gov_wit_net_id: Vec<BasicPrefix>, ch_gov_wit_net_oobi: Vec<Oobi>, 
    ch_gov_wat_net_id: Vec<IdentifierPrefix>, ch_gov_wat_net_oobi: Vec<Oobi>, 
    issuer_id : Arc<Mutex<Identifier>>, n : i32, 
    first_message: MessageWithSignatureAndEventSeal /*es : EventSeal, fm: &[u8], fs: Signature*/) -> bool 
    
{
    let es = first_message.event_seal;
    let fm = first_message.message.as_bytes();
    let fs = first_message.signature;
    let issuer_id_id = issuer_id.lock().await.id().clone();
    let mut to_watch : Vec<ToWatch> = vec![];
    to_watch.push(ToWatch { prefix: fs.get_signer().unwrap().clone(), event_seal: es.clone() });

    let x_handle: tokio::task::JoinHandle<Result<KeriController, Box<dyn Error + Send + Sync>>> = tokio::spawn(async move {

        let controller = KeriController::incept(
            format!("u_{}", n).to_string(), 
            KeriController::pick_m_random_oobi(ch_gov_wit_net_oobi, 2), 
            KeriController::pick_m_random_oobi(ch_gov_wat_net_oobi.clone(), ch_gov_wat_net_oobi.len()-2), 
            1, 
            to_watch, 
            false
        ).await.map_err(|err| Box::new(err) as Box<dyn Error + Send + Sync>)?;

        Ok(controller)

    });

    match x_handle.await {
        Ok(result) => {
            match result {
                Ok(controller) => {
                    // Handle successful result
                    // println!("Waiting Barrier from {}", n);
                    barrier.wait().await;

                    let random_delay_ms = rand::thread_rng().gen_range(0..=200);
                    sleep(Duration::from_millis(random_delay_ms)).await;
                
                    println!("Checking KEL from {}", n);
                    assert!(controller.controller
                        .verify(fm, &fs)
                        .is_ok());
                
                    barrier2.wait().await;
                
                    let fs2: SignatureWithEventSeal = second_signature.recv().await.unwrap();

                    assert!(matches!(
                        controller.controller
                            .verify(fm, &fs2.signature)
                            .unwrap_err(),
                        VerificationError::MoreInfo(MoreInfoError::EventNotFound(_))
                    ));
                
                    // println!("Checking KEL from {}", n);
                    // assert!(ct
                    //     .verify(fm, &fs2)
                    //     .is_ok());



                    // let _ = query_kel(n, id_mutex.clone(), &ks, &issuer_id_id, &fs2.event_seal).await;
                    // controller.query_kel(&fs2.event_seal).await.unwrap();
                    // assert!(controller.controller
                    //     .verify(fm, &fs2.signature)
                    //     .is_ok());

                
                    println!("Finish checking  KEL from {}", n);
                    return true;
                    
                }
                Err(_err) => {
                    println!("{} {:?}", "Error".red(),_err);
                    barrier.wait().await;
                    return false;
                }
            }
        }
        Err(_join_error) => {
            println!("{} {:?}", "Error".red(),_join_error);
            barrier.wait().await;
            return false;
        }
    }



}

// Function to check if a port is open
fn is_port_open(mut addr: String, port: u16) -> bool {
    // Create a socket address by combining the address and port
    if addr == "localhost" {
        addr = "127.0.0.1".to_string();
    }
    let socket_addr = format!("{}:{}", addr, port);
    match socket_addr.parse::<SocketAddr>() {
        Ok(socket_addr) => {
            // Try to connect to the socket address
            if let Ok(_) = TcpStream::connect(socket_addr) {
                println!("Port {} is open", port);
                true
            } else {
                println!("Port {} is closed", port);
                false
            }
        }
        Err(_) => {
            eprintln!("Invalid address: {}", addr);
            false
        }
    }
}
