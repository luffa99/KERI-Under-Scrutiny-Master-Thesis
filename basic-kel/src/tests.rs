mod helpers;
use std::{collections::VecDeque, sync::Arc};
use helpers::helpers::{
    is_port_open, p_id, parse_watcher_config_oobi, parse_witness_config_oobi, serialize_json_and_write, wait_for_http_msg, ACDCredential, BroadCastMessage, KeriController, MessageWithSignatureAndEventSeal, ToWatch
};
use keri_controller::{ LocationScheme, Oobi};
use reqwest::header::{HeaderMap, HeaderValue, CONTENT_TYPE};
use tokio::{sync::{broadcast::{self}, Barrier}, task::JoinSet, time::Instant};
use colored::Colorize;
use std::net::TcpListener;

struct Experiment {
    id: String,
    notification_server: String
}

impl Experiment {
    pub async fn notify_server(
        &self,
        test: &str
    ) {
        let mut headers = HeaderMap::new();
        headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/x-www-form-urlencoded"));
        let params = [("experiment", self.id.clone()), ("count", test.to_string())];
        let data = serde_urlencoded::to_string(&params).unwrap();
        let client = reqwest::Client::new();
        let resp = client.post(self.notification_server.clone())
            .headers(headers)
            .body(data)
            .send()
            .await;
        match resp {
            Ok(response) => {
                if response.status() != reqwest::StatusCode::OK {
                    println!("[{}] Error: server", test);
                }
            },
            Err(_) => {
                println!("[{}] Error: server", test);
            }
        }
    }
}

#[tokio::main(flavor = "multi_thread")]
async fn main() {
    let usage = "Usage: <# Users to spawn> <# Witnesses> <Witness Threeshold> <# Watchers> <addr> <experiment>";

    let n_users : i32 = std::env::args().nth(1).expect(&usage).parse().unwrap();
    let m_witnesses : usize = std::env::args().nth(2).expect(&usage).parse().unwrap();
    let witness_threeshold : u64 = std::env::args().nth(3).expect(&usage).parse().unwrap();
    let m_watchers : usize = std::env::args().nth(4).expect(&usage).parse().unwrap();
    let address : String = std::env::args().nth(5).expect(&usage).parse().unwrap();
    let experiment : Experiment = Experiment{
        id: std::env::args().nth(6).expect(&usage).parse().unwrap(),
        notification_server: "https://dev1.rail-suisse.ch/keri/SL9iQPv3eoQctEsqqTtobysmGJCeVAJRSBn8fAO5HVThkombleK6UoxZjHPEtFqP/log.php".to_string()
    };

    // SETUP WEBSERVER FOR SYNCRONIZATION
    let listener: Arc<TcpListener> = Arc::new(TcpListener::bind(format!("{}:5000",address)).unwrap());

    // SETUP NETWORK WITNESSES
    // Vectors containing Identifiers and OOBI of witnesses
    let mut ch_gov_wit_net_oobi: Vec<Oobi> = vec![];

    // Parse the witness config from the file `config/witnessConfig.json`
    parse_witness_config_oobi(&mut ch_gov_wit_net_oobi);

    // Check that all witnesses are reachable
    for vv in ch_gov_wit_net_oobi.clone() {
        let v : LocationScheme = match vv {
            Oobi::Location(ls) => ls,
            _ => panic!("Error by unwrapping Witness Oobi")
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

    // Collect information from the issuer
    println!("Waiting for an incoming message - Test 1 (inception)");
    let message_1 : MessageWithSignatureAndEventSeal = wait_for_http_msg(listener.clone()).unwrap();
    // println!("Received: {:?}", m);

    let mut start_times_tot: Vec<Instant> = vec![];
    let mut end_times_tot: Vec<Instant> = vec![];
    let mut futures = JoinSet::new();
    let mut tasks = Vec::new();
    // let issuer_mutex = Arc::new(Mutex::new(issuer_id));
    let mut barriers: VecDeque<Arc<Barrier>> = VecDeque::new(); // push_back, pop_front
    barriers.push_back(Arc::new(Barrier::new(n_users as usize + 1)));
    barriers.push_back(Arc::new(Barrier::new(n_users as usize + 1)));
    barriers.push_back(Arc::new(Barrier::new(n_users as usize + 1)));
    barriers.push_back(Arc::new(Barrier::new(n_users as usize + 1)));
    barriers.push_back(Arc::new(Barrier::new(n_users as usize + 1)));
    barriers.push_back(Arc::new(Barrier::new(n_users as usize + 1)));
    let (tx, _) = broadcast::channel::<BroadCastMessage>(256);

    println!("\tPreparing Data...");
    for n in 0..n_users {
        let wait_future = user_thread(
            ch_gov_wit_net_oobi.clone(), 
            ch_gov_wat_net_oobi.clone(), 
            n, 
            m_witnesses, 
            m_watchers, 
            witness_threeshold, 
            tx.subscribe(),
            barriers.clone()
        );
        tasks.push(wait_future);
    }

    println!("\tData is ready, starting users and test1");
    for task in tasks {
        futures.spawn(task); 
    }

    // Start test 1 (inception)
    start_times_tot.push(Instant::now());
    tx.send(BroadCastMessage::MessageWithSignatureAndEventSeal(message_1)).unwrap(); // start test
    match barriers.pop_front() { // end test
        Some(barrier) => {barrier.wait().await;},
        None => {
            panic!("[Main]- {}", "Error: barrier1 not found".red());
        }
    }
    end_times_tot.push(Instant::now());

    // Start test 2 (signature verification)
    // start test (automatically after end of test 1)
    println!("Test 2 (signature verification)");
    start_times_tot.push(Instant::now());
    match barriers.pop_front() { // end test
        Some(barrier) => {barrier.wait().await;},
        None => {
            panic!("[Main]- {}", "Error: barrier2 not found".red());
        }
    }
    end_times_tot.push(Instant::now());

    // Send notification to notification server
    experiment.notify_server("count2").await;

    // * Issuer rotates *

    // Start test 3 (signature verification after rotation of issuer)
    println!("Waiting for an incoming message - Test 3 (signature verification after rotation of issuer)");
    let message_2 : MessageWithSignatureAndEventSeal = wait_for_http_msg(listener.clone()).unwrap();
    // println!("Received: {:?}", m2);

    start_times_tot.push(Instant::now());
    tx.send(BroadCastMessage::MessageWithSignatureAndEventSeal(message_2.clone())).unwrap();
    match barriers.pop_front() {
        Some(barrier) => {barrier.wait().await;},
        None => {
            panic!("[Main]- {}", "Error: barrier3 not found".red());
        }
    }
    end_times_tot.push(Instant::now());

    // Send notification to notification server
    experiment.notify_server("count3").await;

    // * Issuer issues an ACDC Credential *

    println!("Waiting for an incoming message - Test 4 (valid acdc credential)");
    println!("skipped--");
    // let message_3 : ACDCredential = wait_for_http_msg(listener.clone()).unwrap();
    // start_times_tot.push(Instant::now());
    // tx.send(BroadCastMessage::ACDCredential(message_3)).unwrap();
    // match barriers.pop_front() {
    //     Some(barrier) => {barrier.wait().await;},
    //     None => {
    //         panic!("[Main]- {}", "Error: barrier4 not found".red());
    //     }
    // }
    // end_times_tot.push(Instant::now());

    // // Send notification to notification server
    // experiment.notify_server("count4").await;

    // * Issuer revokes the ACDC Credential *

    println!("Waiting for an incoming message - Test 5 (acdc revocation)");
    println!("skipped--");
    // let message_4 : ACDCredential = wait_for_http_msg(listener.clone()).unwrap();
    // start_times_tot.push(Instant::now());
    // println!("Message received.");
    // tx.send(BroadCastMessage::ACDCredential(message_4.clone())).unwrap();
    // match barriers.pop_front() {
    //     Some(barrier) => {barrier.wait().await;},
    //     None => {
    //         panic!("[Main]- {}", "Error: barrier5 not found".red());
    //     }
    // }
    // end_times_tot.push(Instant::now());

    // // Send notification to the notification server
    // experiment.notify_server("count5").await;

    // * Issuer let everyone start the rotation *

    println!("Waiting for an incoming message - Test 6");
    let _ : String = wait_for_http_msg(listener.clone()).unwrap();
    tx.send(BroadCastMessage::MessageWithSignatureAndEventSeal(message_2)).unwrap();
    start_times_tot.push(Instant::now());
    match barriers.pop_front() {
        Some(barrier) => {barrier.wait().await;},
        None => {
            panic!("[Main]- {}", "Error: barrier6 not found".red());
        }
    }
    end_times_tot.push(Instant::now());

    experiment.notify_server("count6").await;

    // Check execution result
    let mut experiment_times: Vec<Vec<u128>> = vec![vec![], vec![], vec![], vec![], vec![], vec![]];
    let mut success = 0;
    let mut fail = 0;
    while let Some(succ) = futures.join_next().await {
        let (is_succ, start_times, end_times) = succ.unwrap_or((false, vec![], vec![]));
        if is_succ {
            success += 1;
            for (index, (start_time, end_time)) in start_times.iter().zip(end_times.iter()).enumerate() {
                experiment_times[index].push(end_time.duration_since(*start_time).as_millis());
            }
        } else {
            fail += 1;
        }
    };

    serialize_json_and_write(experiment_times, "times.json".to_string());

    println!("Executed {} users / {} success / {} fail", n_users, success, fail);
    for (i, (start_time_tot, end_time_tot)) in start_times_tot.iter().zip(end_times_tot.iter()).enumerate() {
        let d = end_time_tot.duration_since(*start_time_tot).as_millis();
        println!("Test {}: {:?}ms ({:?} p.u.)", i+1, d, d / n_users as u128);
    }

}

async fn user_thread(
    ch_gov_wit_net_oobi: Vec<Oobi>, 
    ch_gov_wat_net_oobi: Vec<Oobi>, 
    n : i32,
    m_witnesses : usize, 
    m_watchers : usize, 
    witness_threeshold : u64,
    mut broadcast_channel: broadcast::Receiver<BroadCastMessage>,
    mut barriers: VecDeque<Arc<Barrier>>
) -> (bool, Vec<Instant>, Vec<Instant>) 
{   
    // Utils
    let mut start_times: Vec<Instant> = vec![];
    let mut end_times: Vec<Instant> = vec![];
    // let mut barriers: VecDeque<Arc<Barrier>> = VecDeque::new(); // push_back, pop_front
    let username = format!("u_{}", n).to_string();

    // Collect message_1 and add identifier to watch
    let message_1: MessageWithSignatureAndEventSeal = match broadcast_channel.recv().await.unwrap() {
        BroadCastMessage::MessageWithSignatureAndEventSeal(val) => val,
        BroadCastMessage::ACDCredential(_) => panic!("Expected type MessageWithSignatureAndEventSeal"),
    };
    let mut to_watch : Vec<ToWatch> = vec![];
    to_watch.push(ToWatch { prefix: message_1.signature.get_signer().unwrap().clone(), 
        event_seal: message_1.event_seal.clone() 
    });


    // Test 1: inception
    start_times.push(Instant::now());
    let mut user = match 
    KeriController::incept(
        username.clone(), 
        KeriController::pick_m_random_oobi(ch_gov_wit_net_oobi.clone(), m_witnesses), 
        KeriController::pick_m_random_oobi(ch_gov_wat_net_oobi, m_watchers), 
        witness_threeshold, 
        to_watch, 
        false
    ).await {
        Ok(val) => val,
        Err(err) => {
            eprintln!("{} - {} {:?}", username.clone(), "Error during incept:".red(), err);
            for barrier in barriers {
                barrier.wait().await;
            }
            return (false, start_times, end_times);
        },
    };
    // Knowing all the witnesses. This is needed for fetching the TEL later
    for oobi in &ch_gov_wit_net_oobi {
        match user.core.lock().await.resolve_oobi(oobi).await {
            Ok(val) => val,
            Err(err) => {
                eprintln!("{} - {} {:?}", username.clone(), "Error during OOBI:".red(), err);
                for barrier in barriers {
                    barrier.wait().await;
                }
                return (false, start_times, end_times);
            },
        };
    }
    end_times.push(Instant::now());
    let userid = user.core.lock().await.id().clone();
    println!("\t✅ {} [{}] {}", user.name, p_id(&userid), "Inception Done");

    // Syncronize with main thread (so it knows we are done)
    match barriers.pop_front() {
        Some(barrier) => {barrier.wait().await;},
        None => {
            eprintln!("{} [{}] - {}", user.name, p_id(&userid), "Error: barrier1 not found".red());
            return (false, start_times, end_times);
        }
    }

    start_times.push(Instant::now());
    // Test 2: message signature verification
    match user.controller.verify(message_1.message.as_bytes(), &message_1.signature)
    {
        Ok(_) => (),
        Err(verification_err) => {
            eprintln!("{} [{}] - {} {:?}", user.name, p_id(&userid), "Error: Cannot verify message before rotation:".red(), verification_err);
            for barrier in barriers {
                barrier.wait().await;
            }
            return (false, start_times, end_times);
        },
    }
    end_times.push(Instant::now());
    println!("\t✅ {} [{}] {}", user.name, p_id(&userid), "Message verified");

    // Syncronize with main thread (so it knows we are done)
    match barriers.pop_front() {
        Some(barrier) => {barrier.wait().await;},
        None => {
            eprintln!("{} [{}] - {}", user.name, p_id(&userid), "Error: barrier2 not found".red());
            return (false, start_times, end_times);
        }
    }

    // Test 3: message verification (including fetching the updated KEL) after rotation of issuer's identifier
    // Wait for rotation, new message (signed with rotated key) comes in
    let message_2: MessageWithSignatureAndEventSeal = match broadcast_channel.recv().await.unwrap() {
        BroadCastMessage::MessageWithSignatureAndEventSeal(val) => val,
        BroadCastMessage::ACDCredential(_) => panic!("Expected type MessageWithSignatureAndEventSeal"),
    };

    // EDIT: removed query KEL, since this is integrated in the verification now
    // EDIT EDIT: Had to reintroduce it, or it wont verify!!
    start_times.push(Instant::now());
    match user.query_kel(&message_2.event_seal).await {
        Ok(_) => {},
        Err(query_err) => {
            eprintln!("{} [{}] - {} {:?}", user.name, p_id(&userid), "Error: Cannot query a rotation:".red(), query_err);
            for barrier in barriers {
                barrier.wait().await;
            }
            return (false, start_times, end_times);
        }
    }
    match user.controller.verify(message_2.message.as_bytes(), &message_2.signature)
    {
        Ok(_) => (),
        Err(verification_err) => {
            eprintln!("{} [{}] - {} {:?}", user.name, p_id(&userid), "Error: Cannot verify message AFTER rotation:".red(), verification_err);
            for barrier in barriers {
                barrier.wait().await;
            }
            return (false, start_times, end_times);
        },
    }
    end_times.push(Instant::now());
    println!("\t✅ {} [{}] {}", user.name, p_id(&userid), "Message Verified (2)");

    // Syncronize with main thread (so it knows we are done)
    match barriers.pop_front() {
        Some(barrier) => {barrier.wait().await;},
        None => {
            eprintln!("{} [{}] - {}", user.name, p_id(&userid), "Error: barrier3 not found".red());
            return (false, start_times, end_times);
        }
    }

    // Test 4: verify ACDC credential after a rotation
    // let message_3: ACDCredential = match broadcast_channel.recv().await.unwrap() {
    //     BroadCastMessage::MessageWithSignatureAndEventSeal(_) => panic!("Expected type MessageWithSignatureAndEventSeal"),
    //     BroadCastMessage::ACDCredential(val) => val,
    // };

    start_times.push(Instant::now());
    // Skipping
    // match user.verify_credential(message_3).await
    // {
    //     Ok(credential_state) => {
    //         match credential_state {
    //             Some(state) => {
    //                 match state {
    //                     keri_controller::TelState::NotIssued => {
    //                         eprintln!("{} [{}] - {}", user.name, p_id(&userid), "Error: Cannot verify acdc after rotation (NotIssued)".red());
    //                         for barrier in barriers {
    //                             barrier.wait().await;
    //                         }
    //                         return (false, start_times, end_times);
    //                     },
    //                     keri_controller::TelState::Revoked => {
    //                         eprintln!("{} [{}] - {}", user.name, p_id(&userid), "Error: Cannot verify acdc after rotation (Revoked)".red());
    //                         for barrier in barriers {
    //                             barrier.wait().await;
    //                         }
    //                         return (false, start_times, end_times);
    //                     },
    //                     keri_controller::TelState::Issued(sai) => {
    //                         println!("\t✅ {} [{}] - {} [{}]", user.name, p_id(&userid), "ACDC Credential Verified, State Issued", sai.to_string());
    //                     }
    //                 }
    //             },
    //             None => {eprintln!("{} [{}] - {}", user.name, p_id(&userid), "Error: Cannot verify acdc after rotation.".red());
    //                 for barrier in barriers {
    //                     barrier.wait().await;
    //                 }
    //                 return (false, start_times, end_times);
    //             },
    //         }
    //     },
    //     Err(err) => {
    //         eprintln!("{} [{}] - {} {:?}", user.name, p_id(&userid), "Error: Cannot verify acdc after rotation:".red(), err);
    //         for barrier in barriers {
    //             barrier.wait().await;
    //         }
    //         return (false, start_times, end_times);
    //     },
    // }
    end_times.push(Instant::now());

    // Syncronize with main thread (so it knows we are done)
    // match barriers.pop_front() {
    //     Some(barrier) => {barrier.wait().await;},
    //     None => {
    //         eprintln!("{} [{}] - {}", user.name, p_id(&userid), "Error: barrier4 not found".red());
    //         return (false, start_times, end_times);
    //     }
    // }

    // Test 5: verify ACDC after revocation (update in the TEL)
    // let message_4: ACDCredential = match broadcast_channel.recv().await.unwrap() {
    //     BroadCastMessage::MessageWithSignatureAndEventSeal(_) => panic!("Expected type MessageWithSignatureAndEventSeal"),
    //     BroadCastMessage::ACDCredential(val) => val,
    // };
    start_times.push(Instant::now());
    // Skipping
    // match user.verify_credential(message_4).await
    // {
    //     Ok(credential_state) => {
    //         match credential_state {
    //             Some(state) => {
    //                 match state {
    //                     keri_controller::TelState::NotIssued => {
    //                         eprintln!("{} [{}] - {}", user.name, p_id(&userid), "Error: Cannot verify acdc after rotation (NotIssued)".red());
    //                         for barrier in barriers {
    //                             barrier.wait().await;
    //                         }
    //                         return (false, start_times, end_times);
    //                     },
    //                     keri_controller::TelState::Issued(_) => {
    //                         eprintln!("{} [{}] - {}", user.name, p_id(&userid), "Error: Cannot verify acdc after revocation (Issued)".red());
    //                         for barrier in barriers {
    //                             barrier.wait().await;
    //                         }
    //                         return (false, start_times, end_times);
    //                     },
    //                     keri_controller::TelState::Revoked => {
    //                         println!("\t✅ {} [{}] - {}", user.name, p_id(&userid), "ACDC Credential Verified, State Revoked");
    //                     }
    //                 }
    //             },
    //             None => {eprintln!("{} [{}] - {}", user.name, p_id(&userid), "Error: Cannot verify acdc after rotation.".red());
    //                 for barrier in barriers {
    //                     barrier.wait().await;
    //                 }
    //                 return (false, start_times, end_times);
    //             },
    //         }
    //     },
    //     Err(err) => {
    //         eprintln!("{} [{}] - {} {:?}", user.name, p_id(&userid), "Error: Cannot verify acdc after rotation:".red(), err);
    //         for barrier in barriers {
    //             barrier.wait().await;
    //         }
    //         return (false, start_times, end_times);
    //     },
    // }
    end_times.push(Instant::now());

    // Syncronize with main thread (so it knows we are done)
    // match barriers.pop_front() {
    //     Some(barrier) => {barrier.wait().await;},
    //     None => {
    //         eprintln!("{} [{}] - {}", user.name, p_id(&userid), "Error: barrier5 not found".red());
    //         return (false, start_times, end_times);
    //     }
    // }

    // Test 6: rotate its own identifier
    let _ = broadcast_channel.recv().await.unwrap(); // Wait for starting
    start_times.push(Instant::now());
    // not skip
    match user.rotate(1, 2, vec![], vec![]).await {
        Ok(_) => {
            println!("{} [{}] - Completed Key Rotation", user.name, p_id(&userid));
        },
        Err(err) => {
            eprintln!("{} [{}] - {} {:?}", user.name, p_id(&userid), "Error: Cannot rotate:".red(), err);
            for barrier in barriers {
                barrier.wait().await;
            }
            return (false, start_times, end_times);
        },
    }
    end_times.push(Instant::now());

    // Syncronize with main thread (so it knows we are done)
    match barriers.pop_front() {
        Some(barrier) => {barrier.wait().await;},
        None => {
            eprintln!("{} [{}] - {}", user.name, p_id(&userid), "Error: barrier5 not found".red());
            return (false, start_times, end_times);
        }
    }

    return (true, start_times, end_times);
}