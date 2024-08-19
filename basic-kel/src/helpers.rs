pub mod helpers {
    use std::{collections::HashSet, fmt::Debug, fs::{self, File}, io::{BufRead, BufReader, Read, Write}, net::{SocketAddr, TcpStream}, process::{Command, Stdio}, sync::Arc, time::Duration};
    use acdc::{attributes::InlineAttributes, Attestation};
    use chrono::Utc;
    use colored::Colorize;
    use rand::Rng;
    use said::{derivation::{HashFunction, HashFunctionCode}, sad::{SerializationFormats, SAD}, version::Encode, SelfAddressingIdentifier};
    use tokio::{sync::Mutex, time::{sleep, timeout}};

    use keri_controller::{config::ControllerConfig, controller::Controller, error::ControllerError, identifier::{self, mechanics::MechanicsError, query::{QueryResponse, WatcherResponseError}, Identifier}, BasicPrefix, CryptoBox, EndRole, IdentifierPrefix, KeyManager, LocationScheme, Oobi, SelfSigningPrefix, TelState};
    use keri_core::{event::sections::seal::EventSeal, event_message::signature::Signature, transport::TransportError};
    use tempfile::Builder;
    use serde::{de::Error as _, Deserialize, Serialize};
    use serde::de::DeserializeOwned;
    use std::net::TcpListener;
    use std::str::FromStr;
    use rand::seq::SliceRandom;
    use rand::thread_rng;

    macro_rules! gcore {
        ($mutex:expr) => {
            $mutex.core.lock().await
        };
    }

    pub struct KeriController {
        pub core: Arc<Mutex<Identifier>>,
        pub controller: Arc<Controller>,
        pub key_manager: CryptoBox,
        pub name: String,
        pub witnesses: Vec<Oobi>,   // Pool of trusted witnesses
        pub watchers: Vec<Oobi>     // Pool of trusted watchers (if any)
    }

    impl KeriController {

        pub async fn incept(
            name: String,
            witnesses: Vec<Oobi>,
            watchers: Vec<Oobi>,
            initial_witness_threeshold: u64,
            identifiers_to_watch: Vec<ToWatch>,
            send_controller_oobi_to_watchers: bool
        ) -> Result<Self, ControllerError> {
            if witnesses.len() < 1 {
                return Err(ControllerError::OtherError("\tWitness array is empty".to_string()));
            }

            // Establish identifier
            // Setup database path and key manager.
            // Note: "name" MUST be unique, or you will have issues with the local database
            let database_path = Builder::new().prefix(&name).tempdir().unwrap();
            let key_manager = CryptoBox::new().unwrap();

            // The `Controller` structure aggregates all known KEL events (across all
            // identifiers) and offers functions for retrieving them, verifying the
            // integrity of new events, and conducting signature verification.
            let controller = Arc::new(Controller::new(ControllerConfig {
                db_path: database_path.path().to_owned(),
                ..Default::default()
            })?);

            // Incept identifier.
            // The `Identifier` structure facilitates the management of the
            // Key Event Log specific to a particular identifier.
            let pk = BasicPrefix::Ed25519(key_manager.public_key());
            let npk = BasicPrefix::Ed25519(key_manager.next_public_key());

            // Create inception event, that needs `initial_witness_threeshold` witness receipt to be accepted.
            let icp_event = controller
                .incept(
                    vec![pk],
                    vec![npk],
                    witnesses.clone().into_iter()
                                    .filter_map(|oobi| {
                                        if let Oobi::Location(location) = oobi {
                                            Some(location)
                                        } else {
                                            // Provided Oobi is not of type `Location`, 
                                            // hence cannot extract a `LocationScheme`
                                            None
                                        }
                                    })
                                    .collect(),
                    initial_witness_threeshold
                )
                .await?;
            
            // Inception event needs to be signed
            let signature =
                SelfSigningPrefix::Ed25519Sha512(key_manager.sign(icp_event.as_bytes()).unwrap());
            let identifier: Identifier =
                controller.finalize_incept(icp_event.as_bytes(), &signature)?;
            let identifier_id = identifier.id().clone();
            // Need to create a mutex; couldn't find any other solution to fit it into exponential_backoff
            let identifier_mutex = Arc::new(Mutex::new(identifier));
                        
            // Publish event to actor's witnesses
            Self::exponential_backoff( 
                ||  async {
                    identifier_mutex.lock().await.notify_witnesses().await
                }, identifier::mechanics::MechanicsError::OtherError(
                    "Reached maximum number of retry (incept, publishing icp to witnesses)".to_string()
                )
            ).await?;
            
            // Collect receipts from witnesses
            // NOTE: the argument of query_mailbox requires a vector, hence
            // we have first to build the Vec<BasicPrefix> to be passed as an argument
            let witnesses_basicprefixes: Vec<BasicPrefix> = Self::convert_oobi_to_basic_prefix(witnesses.clone())?;

            let queries = identifier_mutex.lock().await
                .query_mailbox(&identifier_id, &witnesses_basicprefixes)?;

            for qry in queries
            {
                let signature = SelfSigningPrefix::Ed25519Sha512(
                    key_manager.sign(&qry.encode().unwrap()).unwrap(),
                );
                Self::exponential_backoff(
                    || async {
                    identifier_mutex.lock().await
                        .finalize_query_mailbox(vec![(qry.clone(), signature.clone())])
                        .await
                    }, identifier::mechanics::MechanicsError::OtherError(
                            "Reached maximum number of retry (incept, publishing icp to witnesses)".to_string()
                    )                
                ).await?;
            }

            // Check if verifying identifier was established successfully
            identifier_mutex.lock().await.get_last_establishment_event_seal()?;
            println!("Incepted: {} [{}]", &name, p_id(&identifier_id));

            let instance = KeriController {
                core: identifier_mutex,
                controller: controller,
                key_manager,
                name,
                witnesses,
                watchers,
            };

            // Initialize watchers, if any provided
            // Now setup watchers, to be able to query of signing identifier KEL.
            for wat_oobi in instance.watchers.clone() {
                // Resolve watcher oobi
                gcore!(instance).resolve_oobi(&wat_oobi).await?;
        
                // Generate and sign event, that will be sent to watcher, so it knows to act
                // as verifier's watcher.
                let wat_id = match wat_oobi {
                    Oobi::Location(loc_scheme) => Ok(loc_scheme.eid),
                    Oobi::EndRole(_) => Err(ControllerError::OtherError("\tInvalid Watcher's IdentifierPrefix".to_string())),
                }?;
                let add_watcher = gcore!(instance).add_watcher(wat_id.clone())?;
                let signature = SelfSigningPrefix::Ed25519Sha512(
                    instance.key_manager.sign(add_watcher.as_bytes()).unwrap(),
                );
        
                gcore!(instance)
                    .finalize_add_watcher(add_watcher.as_bytes(), signature)
                    .await?;
                
                if !gcore!(instance).watchers().unwrap().contains(&wat_id) {
                    return Err(ControllerError::OtherError("\tAn error occurred while adding a Watcher".to_string()));
                }

                println!("\tAdded [{}] as watcher for {} [{}]", p_id(&wat_id), instance.name, p_id(&gcore!(instance).id()));
            }

            if identifiers_to_watch.len() > 0 {
                Self::ask_watchers_to_watch_identifiers(
                    &instance, 
                    identifiers_to_watch
                ).await?;
            }

            // Sending its own OOBI to the set-upped WATCHERS
            if send_controller_oobi_to_watchers {
                // Select a random Witness as Witness for watching an identifier
                let random_index = rand::thread_rng().gen_range(0..witnesses_basicprefixes.len());

                let signer_oobi = EndRole {
                    cid: identifier_id.clone(),
                    role: keri_core::oobi::Role::Witness,
                    eid: keri_controller::IdentifierPrefix::Basic(witnesses_basicprefixes[random_index].clone()),
                };
                
                Self::exponential_backoff(
                    || async {
                        gcore!(instance)
                        .send_oobi_to_watcher(
                            &identifier_id.clone(),
                            &Oobi::EndRole(signer_oobi.clone())
                        )
                        .await
                    }, ControllerError::OtherError(format!("\t[{}] {} (watching) : {}", instance.name, "Error".red(), "Timed out OOBI"))
                ).await?;

                println!("\t[{}] {}", instance.name, "Sent OOBI To Watchers")
            }
            
            return Ok(instance);
        }

        async fn ask_watchers_to_watch_identifiers(
            controller: &KeriController, 
            to_watch: Vec<ToWatch>
        ) -> Result<(), ControllerError> {
            // Check if watchers are setup correctly
            assert!(
                gcore!(controller).watchers().unwrap().len() > 0
            );

            // Send signers oobis to verifier's watchers and query for results.
            for signer_identifier in &to_watch {
                println!("\tAsking {} [{}]'s watchers to watch [{}]", controller.name, p_id(&gcore!(controller).id()), p_id(&signer_identifier.prefix.clone()));

                assert!(gcore!(controller).get_last_establishment_event_seal().is_ok());
                
                // Query watchers about the added identifiers
                let qry_watcher = gcore!(controller).query_watchers(&signer_identifier.event_seal)?;
                for qry in qry_watcher {
                    let signature = SelfSigningPrefix::Ed25519Sha512(controller.key_manager.sign(&qry.encode()?)?);
                    let qry_clone = qry.clone();
                    let query_and_signature = vec![(qry, signature)];
                    Self::exponential_backoff(
                        || async {
                            let (value, errors) = gcore!(controller).finalize_query(query_and_signature.clone()).await;
                            if errors.is_empty() /*&& value == QueryResponse::Updates*/ {
                                Ok(value)
                            } else {
                                eprintln!("{:?}; query was: {:?}", errors, qry_clone);
                                Err(keri_controller::identifier::query::WatcherResponseError::UnexpectedResponse)
                            }
                        }, 
                        WatcherResponseError::SendingError(
                            keri_controller::communication::SendingError::TransportError(
                                TransportError::NetworkError("Reached maximum number of retry (ask_watchers_to_watch_identifier, finalize_query)".to_string())
                            )
                        )
                    ).await?;
                }
            }

            Ok(())
        }

        pub async fn rotate(
            &mut self,
            new_next_threeshold: u64,
            new_witness_threeshold: u64,
            witness_to_add: Vec<LocationScheme>,
            witness_to_remove: Vec<BasicPrefix>
        ) -> Result<(), MechanicsError>{
            println!("{} [{}] Starts Rotation", self.name, p_id(&gcore!(self).id()));

            // Rotate keys
            self.key_manager.rotate()?;
            let pk = BasicPrefix::Ed25519(self.key_manager.public_key());
            let npk = BasicPrefix::Ed25519(self.key_manager.next_public_key());
            
            // Rotate locally
            let rotation_event = gcore!(self)
                .rotate(vec![pk], vec![npk], new_next_threeshold, witness_to_add, witness_to_remove, new_witness_threeshold)
                .await?;
            
            // Finalize rotation
            let signature = SelfSigningPrefix::Ed25519Sha512(self.key_manager.sign(rotation_event.as_bytes()).unwrap());
            Self::exponential_backoff( 
                ||  async {
                    gcore!(self)
                        .finalize_rotate(rotation_event.as_bytes(), signature.clone())
                        .await
                }, identifier::mechanics::MechanicsError::OtherError(
                    "Reached maximum number of retry (rotate, finalize_rotate)".to_string()
                )
            ).await?;
        
            // Publish event to actor's witnesses
            Self::exponential_backoff( 
                ||  async {
                    gcore!(self).notify_witnesses().await
                }, identifier::mechanics::MechanicsError::OtherError(
                    "Reached maximum number of retry (rotate, notify_witnesses)".to_string()
                )
            ).await?;
        
            // Querying witnesses to get receipts
            let issuer_id_id = gcore!(self).id().clone();
            let witnesses_basicprefixes: Vec<BasicPrefix> = match Self::convert_oobi_to_basic_prefix(self.witnesses.clone()) {
                Ok(value) => Ok(value),
                Err(_) => Err(MechanicsError::OtherError("Error converting witnesses Oobi to basicprefixes in rotate".to_string())),
            }?;
            let iterate = gcore!(self)
                .query_mailbox(
                    &issuer_id_id,
                    &witnesses_basicprefixes,
                )
                .unwrap();
            for qry in iterate
            {
                let signature =
                    SelfSigningPrefix::Ed25519Sha512(self.key_manager.sign(&qry.encode().unwrap()).unwrap());
                    Self::exponential_backoff(
                        || async {
                            gcore!(self)
                                .finalize_query_mailbox(vec![(qry.clone(), signature.clone())])
                                .await
                        }, identifier::mechanics::MechanicsError::OtherError(
                            "Reached maximum number of retry (rotate, notify_witnesses)".to_string()
                        )
                    ).await?;
            }
            println!("{} [{}] Ends Rotation", self.name, p_id(&issuer_id_id));
            
            Ok(())
        }

        pub async fn sign_message(
            &self,
            msg: String
        ) -> Result<MessageWithSignatureAndEventSeal, ControllerError> {
            let message_signature = vec![SelfSigningPrefix::Ed25519Sha512(
                self.key_manager.sign(msg.as_bytes())?,
            )];
            let signature = gcore!(self).sign_data(msg.as_bytes(), &message_signature)?;
            let current_event_seal = gcore!(self).get_last_establishment_event_seal()?;

            Ok(MessageWithSignatureAndEventSeal{
                signature: signature,
                event_seal: current_event_seal,
                message: msg
            })
        }

        pub async fn query_kel(
            &self,
            event_seal: &EventSeal
        ) -> Result<QueryResponse, WatcherResponseError> {
             // Query kel of signing identifier
            let queries_and_signatures: Vec<_> = gcore!(self)
                .query_watchers(&event_seal).unwrap()
                .into_iter()
                .map(|qry| {
                    let signature = SelfSigningPrefix::Ed25519Sha512(
                        self.key_manager.sign(&qry.encode().unwrap()).unwrap(),
                    );
                    (qry, signature)
                })
                .collect();

            Self::exponential_backoff(|| async {
                let (q, err) = gcore!(self)
                    .finalize_query(queries_and_signatures.clone())
                    .await;
                if !err.is_empty() /*|| q == QueryResponse::NoUpdates*/ {
                    if !err.is_empty() {
                        eprintln!("{} [{}] error in (finalize_query, query_tel): {:?}. Request was: {:?}", self.name, p_id(&gcore!(self).id()), err[0], event_seal);
                    } else {
                        eprintln!("{} [{}] waiting in finalize_query: NoUpdates", self.name, p_id(&gcore!(self).id()));
                    }
                    // We return an err s.t. the query is repeated following exponential backoff
                    // TODO: actually return the error from the watcher
                    Err(WatcherResponseError::SendingError(
                        keri_controller::communication::SendingError::ActorInternalError(
                            keri_core::actor::error::ActorError::GeneralError(
                                    "Either Watcher Error or NoUpdates".to_string()
                                )
                            )
                        )   
                    )
                } else {
                    Ok(q)
                }
            }, WatcherResponseError::SendingError(
                keri_controller::communication::SendingError::ActorInternalError(
                        keri_core::actor::error::ActorError::GeneralError("Cannot finalize query in query_kel".to_string())
                    )
                )
            ).await
        }

        pub async fn incept_tel(
            &self
        ) -> Result<(), ControllerError>{
            let id_id = gcore!(self).id().clone();
            println!("Incepting TEL for {} [{}]", self.name, p_id(&id_id));

            // Incept registry. It'll generate ixn (registry inception event, interaction event) that need to be signed.
            let (tel_id, vcp_ixn) = gcore!(self).incept_registry()?;

            // Sign interaction message for registry inception, and add it to the KEL (anchoring)
            // And notify witnesses
            let signature = SelfSigningPrefix::Ed25519Sha512(self.key_manager.sign(&vcp_ixn).unwrap());
            gcore!(self).finalize_incept_registry(&vcp_ixn, signature).await.unwrap();

            gcore!(self).notify_witnesses().await.unwrap();

            let queries = gcore!(self).query_mailbox(&id_id, &Self::convert_oobi_to_basic_prefix(self.witnesses.clone())?)?;
            for qry in queries {
                let signature = SelfSigningPrefix::Ed25519Sha512(self.key_manager.sign(&qry.encode()?)?);
                Self::exponential_backoff(|| async {
                    gcore!(self).finalize_query_mailbox(vec![(qry.clone(), signature.clone())]).await
                }, 
                    MechanicsError::OtherError("error in incept_tel while finalize_query_mailbox".to_string())
                ).await?;
            }

            // To find issuer`s TEL, needs to provide to watcher its oobi
            // println!("\n\nRegistry id: {}", gcore!(self).registry_id().unwrap().clone());
            // Telling the watchers: "You can find my TEL if you ask this witness"
            // EDIT: We do this as a verifier, see verify_credential
            // for wit in Self::convert_oobi_to_basic_prefix(self.witnesses.clone()).unwrap() {
            //     let signer_tel_oobi = EndRole {
            //         cid: gcore!(self).registry_id().unwrap().clone(),
            //         role: keri_core::oobi::Role::Witness,
            //         eid: keri_controller::IdentifierPrefix::Basic(
            //             wit
            //         ),
            //     };
    
            //     gcore!(self)
            //         .send_oobi_to_watcher(&id_id, &Oobi::EndRole(signer_tel_oobi))
            //         .await?;
            // }
            

            println!("\tIncepted TEL [{}, {}] of {} [{}]", p_id(&tel_id), p_id(&gcore!(self).registry_id().unwrap().clone()), self.name, p_id(&id_id));
            Ok(())
        }

        pub async fn issue_private_acdc (
            &self,
            attributes: InlineAttributes,
            issuee_id: Option<IdentifierPrefix>
        ) -> Result<ACDCredential, ControllerError>
        { 
            // Check if a registry exists
            let reg_id = match gcore!(self).registry_id() {
                Some(regid) => Some(regid.clone()),
                None => None
            };
            match reg_id {
                Some(_) => (),
                None => {
                    println!("{}", format!("{} [{}] - Registry has not been initialized", self.name, p_id(&gcore!(self).id())).yellow());
                    Self::incept_tel(self).await?;
                }, // Create a registry first!
            }
            let issuer_id_id = gcore!(self).id().clone();
            let issuer_registry_id = gcore!(self).registry_id().unwrap().clone();
            let acdc_attestation: Attestation = match issuee_id {
                // The ACDC is targeted
                Some(target_id) => {
                    Attestation::new_private_targeted(
                        &issuer_id_id.to_string(),
                        &target_id.to_string(),
                        issuer_registry_id.to_string(),
                        HashFunction::from(HashFunctionCode::Blake3_256)
                            .derive(&[0; 30])
                            .to_string(),
                            attributes,
                    )
                },
    
                // The ADCD is untargeted
                None => {
                    Attestation::new_private_untargeted(
                        &gcore!(self).id().to_string(), 
                        issuer_registry_id.to_string(), 
                        HashFunction::from(HashFunctionCode::Blake3_256)
                            .derive(&[0; 30])
                            .to_string(), 
                        attributes)
                }
            };
            
            // Verify binding
            // let derivation_data =
            //     acdc_attestation.derivation_data(&HashFunctionCode::Blake3_256, &SerializationFormats::JSON);
            // assert!(acdc_attestation.digest.clone().unwrap().verify_binding(&derivation_data));
    
            let credential = acdc_attestation
                            .encode(&HashFunctionCode::Blake3_256, &SerializationFormats::JSON)
                            .unwrap();
            // let credential_string = String::from_utf8(credential.clone()).unwrap();
            let credential_said =
                HashFunction::from(HashFunctionCode::Blake3_256).derive(&credential);
            
            // Issue credential. It'll generate ixn message, that needs to be signed and sent to the witnesses
            let (vc_hash, iss_ixn) = gcore!(self).issue(credential_said.clone()).unwrap();
            let sai: said::SelfAddressingIdentifier = match &vc_hash {
                IdentifierPrefix::SelfAddressing(sai) => sai.clone(),
                _ => unreachable!(),
            };
    
            let signature = SelfSigningPrefix::Ed25519Sha512(self.key_manager.sign(&iss_ixn).unwrap());
            gcore!(self).finalize_issue(&iss_ixn, signature).await.unwrap();

            // gcore!(self).notify_witnesses().await.unwrap();
            Self::exponential_backoff( 
                ||  async {
                    gcore!(self).notify_witnesses().await
                }, identifier::mechanics::MechanicsError::OtherError(
                    "Reached maximum number of retry (incept, publishing icp to witnesses)".to_string()
                )
            ).await?;

            let queries = gcore!(self).query_mailbox(
                &issuer_id_id, 
                &Self::convert_oobi_to_basic_prefix(self.witnesses.clone()).unwrap()
            ).unwrap();
            for qry in queries {
                let signature = SelfSigningPrefix::Ed25519Sha512(self.key_manager.sign(&qry.encode().unwrap()).unwrap());
                // let _act = gcore!(self).finalize_query_mailbox(vec![(qry, signature)]).await.unwrap();
                Self::exponential_backoff(
                    || async {
                    gcore!(self)
                        .finalize_query_mailbox(vec![(qry.clone(), signature.clone())])
                        .await
                    }, identifier::mechanics::MechanicsError::OtherError(
                            "Reached maximum number of retry (incept, publishing icp to witnesses)".to_string()
                    )                
                ).await?;
            }
    
            let vc_state = gcore!(self).find_vc_state(&sai).unwrap();
            assert!(matches!(vc_state, Some(TelState::Issued(_))));
    
            // let issued_value = match &vc_state {
            //     Some(TelState::Issued(sai)) => {
            //         IdentifierPrefix::SelfAddressing(sai.clone())
            //     },
            //     Some(_) => todo!(),
            //     None => todo!()
            // };
    
            // Now publish corresponding tel events to backers. Verifier can find them there.
            Self::exponential_backoff( 
                ||  async {
                    gcore!(self).notify_backers().await
                }, identifier::mechanics::MechanicsError::OtherError(
                    "Reached maximum number of retry (notify_bakers, issue_private_acdc)".to_string()
                )
            ).await?;
    
            println!("{} [{}] - Issues message [{}]", self.name, p_id(&issuer_id_id), &credential_said);
            // println!("\n{}\n", String::from_utf8(credential).unwrap());
            // println!("\n{:?}\n", credential_said);
            // println!("\n{:?}\n", sai);
            // println!("\n{:?}\n", vc_hash);
    
            Ok(ACDCredential{
                content: acdc_attestation,
                sai: credential_said,
                vc_identifier: vc_hash,
                event_seal: gcore!(self).get_last_event_seal()?
            })
        }

        pub async fn revoke_acdc(
            &self,
            credential: &mut ACDCredential
        ) -> Result<(), ControllerError> 
        {
            // Revoke issued message
            let rev_ixn = gcore!(self).revoke(&credential.sai)?;
            let sai = match &credential.vc_identifier {
                IdentifierPrefix::SelfAddressing(sai) => sai.clone(),
                _ => unreachable!(),
            };

            let signature = SelfSigningPrefix::Ed25519Sha512(self.key_manager.sign(&rev_ixn)?);
            gcore!(self).finalize_revoke(&rev_ixn, signature).await?;

            Self::exponential_backoff( 
                ||  async {
                    gcore!(self).notify_witnesses().await
                }, identifier::mechanics::MechanicsError::OtherError(
                    "Reached maximum number of retry (notify_witnesses, revoke_acdc)".to_string()
                )
            ).await?;

            let issuer_id_id = gcore!(self).id().clone();
            let queries = gcore!(self).query_mailbox(
                &issuer_id_id, 
                &Self::convert_oobi_to_basic_prefix(self.witnesses.clone()).unwrap()
            ).unwrap();
            for qry in queries {
                let signature = SelfSigningPrefix::Ed25519Sha512(self.key_manager.sign(&qry.encode().unwrap()).unwrap());
                // let _act = gcore!(self).finalize_query_mailbox(vec![(qry, signature)]).await.unwrap();
                Self::exponential_backoff(
                    || async {
                    gcore!(self)
                        .finalize_query_mailbox(vec![(qry.clone(), signature.clone())])
                        .await
                    }, identifier::mechanics::MechanicsError::OtherError(
                            "Reached maximum number of retry (incept, publishing icp to witnesses)".to_string()
                    )                
                ).await?;
            }
            // Tel events are accepted in
            let vc_state = gcore!(self).find_vc_state(&sai).unwrap();
            assert!(matches!(vc_state, Some(TelState::Revoked)));
            // Now publish corresponding tel events to backers. Verifier can find them there.
            Self::exponential_backoff( 
                ||  async {
                    gcore!(self).notify_backers().await
                }, identifier::mechanics::MechanicsError::OtherError(
                    "Reached maximum number of retry (notify_bakers, revoke_acdc)".to_string()
                )
            ).await?;

            credential.event_seal = gcore!(self).get_last_event_seal()?;

            Ok(())
        }

        pub async fn verify_credential(
            &self,
            credential: ACDCredential
        ) -> Result<Option<TelState>, MechanicsError>
        { 
            let sai: said::SelfAddressingIdentifier = match &credential.vc_identifier {
                IdentifierPrefix::SelfAddressing(sai) => sai.clone(),
                _ => unreachable!(),
            };
        
            // Try to verify it
            // verifier needs to have issuer's KEL to accept TEL events. Query it's
            // watcher for it.
            // `last_event_seal`, `registry_id` and `vc_hash` should be provided to
            // verifier by issuer.
            // println!("Querying KEL");
            // sleep(Duration::from_secs(5)).await;
            Self::query_kel(
                self,
                &credential.event_seal
            ).await.unwrap();

            // println!("Querying OOBI");
            // sleep(Duration::from_secs(5)).await;
            let id = gcore!(self).id().clone();

            let selected_wit = Self::convert_oobi_to_basic_prefix(
                // vec![self.witnesses.choose(&mut thread_rng()).unwrap().clone()]
                vec![self.witnesses[0].clone()] // Try to always provide the same witness
            ).unwrap()[0].clone();
            match Self::exponential_backoff(|| async {
                    let signer_tel_oobi = EndRole {
                        cid: credential.content.registry_identifier.parse().unwrap(),
                        role: keri_core::oobi::Role::Witness,
                        eid: keri_controller::IdentifierPrefix::Basic(selected_wit.clone()),
                    };

                    // This message tells to my watchers "you can find the registry (cid) by quering the witness (role) with that id (eid)"
                    gcore!(self)
                        .send_oobi_to_watcher(&id, &Oobi::EndRole(signer_tel_oobi.clone()))
                        .await
                }, 
                ControllerError::OtherError("Unable to send_oobi_to_watcher in verify_credential".to_string())
            ).await {
                Ok(_) => (),
                Err(_) => return Err(MechanicsError::OtherError("Unable to send_oobi_to_watcher in verify_credential".to_string())),
            }
            println!("{} - Choosing witness {}", self.name, p_id(&IdentifierPrefix::Basic(selected_wit)));
    
            // Query witness about issuer's TEL.


            // println!("Registry id: {}", credential.content.registry_identifier);
            // sleep(Duration::from_secs(5)).await;
            Self::exponential_backoff(|| async {
                let qry = gcore!(self).query_tel(
                    credential.content.registry_identifier.parse().unwrap(), 
                    credential.vc_identifier.clone()
                ).unwrap();
                
                let signature =
                    SelfSigningPrefix::Ed25519Sha512(self.key_manager.sign(&qry.clone().encode().unwrap()).unwrap());
    
                Self::exponential_backoff(|| async {
                    gcore!(self)
                    .finalize_query_tel(qry.clone(), signature.clone())
                    .await
                }, 
                    MechanicsError::OtherError("Unable to finalize_query_tel in verify_credential".to_string())
                ).await?;

                match gcore!(self).find_vc_state(&sai).unwrap() {
                    Some(_) => Ok(()),
                    None => Err(MechanicsError::OtherError("Unable to find_vc_state in verify_credential".to_string())),
                }
            }, 
                MechanicsError::OtherError("Unable to query about TEL in verify_credential".to_string())
            ).await?;
            
            // Return the non-None state of credential
            Ok(gcore!(self).find_vc_state(&sai).unwrap())
        }

        async fn exponential_backoff<F, Fut, T, E>(func: F, default_err: E) -> Result<T, E>
        where
            F: Fn() -> Fut,
            Fut: std::future::Future<Output = Result<T, E>>,
            E: Debug,
        {
            let random_delay_ms: u64 = rand::thread_rng().gen_range(0..=400);
            let mut delay = 1000 + 200 - random_delay_ms;
            static MAX_ATTEMPTS: u32 = 5;
            static MAX_TIMEOUT: u64 = 11;

            for attempt in 0..MAX_ATTEMPTS {
                match timeout(Duration::from_secs(MAX_TIMEOUT), func()).await {
                    Ok(result) => match result {
                        Ok(result) => return Ok(result),
                        Err(e) => {
                            eprintln!("Attempt {} failed: {:?}. Retrying in {} ms...", attempt + 1, e, delay);
                            // Introduce a random delay up to 20%
                            let random_delay_ms: u64 = rand::thread_rng().gen_range(0..=((delay as f64 * 0.2) as u64));
                            delay = delay + random_delay_ms;
                            if attempt < MAX_ATTEMPTS-1 {
                                sleep(Duration::from_millis(delay)).await;
                                delay *= 2;
                            }
                        }
                    },
                    Err(_e) => {
                        eprintln!("Attempt {} timed out. Retrying in {} ms...", attempt + 1, delay);
                        // Introduce a random delay up to 20%
                        let random_delay_ms: u64 = rand::thread_rng().gen_range(0..=((delay as f64 * 0.2) as u64));
                        delay = delay + random_delay_ms;
                        if attempt < MAX_ATTEMPTS-1 {
                            sleep(Duration::from_millis(delay)).await;
                            delay *= 2;
                        }
                    }
                }
            }

            return Err(default_err);
        }

        pub fn convert_oobi_to_basic_prefix (
            witnesses: Vec<Oobi>
        ) -> Result<Vec<BasicPrefix>, ControllerError>
        {
            let mut witnesses_basicprefixes: Vec<BasicPrefix> = vec![];
            for witness in witnesses {
                if let Oobi::Location(location) = witness {
                    if let IdentifierPrefix::Basic(basic) = location.eid {
                        witnesses_basicprefixes.push(basic.clone());
                    } else {
                        return Err(ControllerError::OtherError("\tInvalid Witness BasicPrefix".to_string()));
                    }
                } else {
                    return Err(ControllerError::OtherError("\tInvalid Witness BasicPrefix".to_string()));
                }
            }
            Ok(witnesses_basicprefixes)
        }

        pub fn pick_m_random_oobi(
            original: Vec<Oobi>,
            m: usize
        ) -> Vec<Oobi>
        {
            let m_rand_indexes = generate_unique_random_numbers(m, original.len());
            let mut ans: Vec<Oobi> = vec![];
            for i in m_rand_indexes {
                ans.push(original[i].clone());
            }
            ans
        }
    }

    #[derive(Clone)]
    #[derive(Debug, Serialize, Deserialize)]
    pub struct ACDCredential {
        pub content: Attestation,
        pub sai: SelfAddressingIdentifier,
        pub vc_identifier: IdentifierPrefix, // Reference to inception event of ACDC issuance,
        pub event_seal: EventSeal
    }

    impl ACDCredential {
        pub fn encode(
            &self
        ) -> Vec<u8> {
            self.content
                .encode(&HashFunctionCode::Blake3_256, &SerializationFormats::JSON)
                .unwrap()
        }

        pub fn encode_str(
            &self
        ) -> String
        {
            String::from_utf8(Self::encode(self)).unwrap()
        }
    }

    #[allow(dead_code)]
    #[derive(Deserialize, Debug)]
    pub struct Message {
        text: String,
    }

    #[allow(dead_code)]
    #[derive(Clone, Debug, Serialize, Deserialize)]
    pub struct MessageWithSignatureAndEventSeal {
        pub signature: Signature,
        pub event_seal: EventSeal, // In theory, should be included in signature when applicable
        pub message: String
    }

    // Data structure to be sent for setting up watchers to watch an identifier
    #[allow(dead_code)]
    #[derive(Clone, Debug, Serialize, Deserialize)]
    pub struct ToWatch {
        pub prefix: IdentifierPrefix,
        pub event_seal: EventSeal // Used for the query
    }

    #[derive(Clone)]
    #[derive(Debug, Deserialize, Serialize)]
    pub enum BroadCastMessage {
        MessageWithSignatureAndEventSeal(MessageWithSignatureAndEventSeal),
        ACDCredential(ACDCredential)
    }

    #[allow(dead_code)]
    pub fn start_witness(config_file: &str, show_wit_wat_debug: bool) {

        let mut cmd = Command::new("./target_from_keriox/debug/witness");
    
        // Add arguments to the command
        cmd.arg("-c");
        cmd.arg(format!("./config/{}", config_file));
    
        // Set up stdout and stderr to be piped
        if !show_wit_wat_debug {
            cmd.stdout(Stdio::null()).stderr(Stdio::inherit());
        }
        // Spawn the command asynchronously
        cmd.spawn().expect("Unable to start witness process");
    }
    
    #[allow(dead_code)]
    pub fn start_watcher(config_file: &str, show_wit_wat_debug: bool) {
    
        let mut cmd = Command::new("./target_from_keriox/debug/watcher");
    
        // Add arguments to the command
        cmd.arg("-c");
        cmd.arg(format!("./config/{}", config_file));
    
        // Set up stdout and stderr to be piped
        if !show_wit_wat_debug {
            cmd.stdout(Stdio::null()).stderr(Stdio::inherit());
        }
    
        // Spawn the command asynchronously
        cmd.spawn().expect("Unable to start watcher process");
    }

    pub fn generate_unique_random_numbers(m: usize, n: usize) -> Vec<usize> {
        if m > n {
            panic!("Cannot generate more unique numbers than the range size");
        }
    
        let mut rng = rand::thread_rng();
        let mut numbers = HashSet::new();
    
        while numbers.len() < m {
            let num = rng.gen_range(0..n);
            numbers.insert(num);
        }
    
        numbers.into_iter().collect()
    }    

    #[allow(dead_code)]
    pub async fn init_identifier_with_watcher(
        name: &str, 
        wit_net_id: &Vec<BasicPrefix>, 
        wit_net_oobi: &Vec<LocationScheme>, 
        wat_net_id: Vec<IdentifierPrefix>, 
        wat_net_oobi: Vec<Oobi>, 
        to_watch: Vec<ToWatch>, // Identifier to watch!
        number_of_witnesses: usize,
        number_of_watchers: usize,
        witness_threeshold: u64,
        send_oobi: bool
        
    ) -> Result<(Identifier, Arc<Controller>, CryptoBox), ControllerError> {

        // Select m random witnesses
        let m_rand_witnesses_indexes = generate_unique_random_numbers(number_of_witnesses, wit_net_id.len());

        // Create Network of m Witnesses and use it
        let mut wit_net_id_two: Vec<BasicPrefix> = vec![];
        let mut wit_net_oobi_two: Vec<LocationScheme> = vec![];
        for i in m_rand_witnesses_indexes {
            wit_net_id_two.push(wit_net_id[i].clone());
            wit_net_oobi_two.push(wit_net_oobi[i].clone());
        }

        let (mut verifier_identifier, verifier_controller, verifier_key_manager) 
            = init_identifier_db_and_witnesses(name, &wit_net_id_two, &wit_net_oobi_two, witness_threeshold).await.unwrap();

        // Create network of n-2 watchers
        let m_rand_watchers_indexes = generate_unique_random_numbers(number_of_watchers, wat_net_id.len());

        // Create network of m Watchers 
        let mut wat_net_id_two: Vec<IdentifierPrefix> = vec![];
        let mut wat_net_oobi_two: Vec<Oobi> = vec![];
        for i in m_rand_watchers_indexes {
            wat_net_id_two.push(wat_net_id[i].clone());
            wat_net_oobi_two.push(wat_net_oobi[i].clone());
        }
    
        // Now setup watcher, to be able to query of signing identifier KEL.
        for (wat_id, wat_oobi) in wat_net_id_two.iter().zip(wat_net_oobi_two) {
            // Resolve watcher oobi
            verifier_identifier.resolve_oobi(&wat_oobi).await?;
    
            // Generate and sign event, that will be sent to watcher, so it knows to act
            // as verifier's watcher.
            let add_watcher = verifier_identifier.add_watcher(wat_id.clone())?;
            let signature = SelfSigningPrefix::Ed25519Sha512(
                verifier_key_manager.sign(add_watcher.as_bytes()).unwrap(),
            );
    
            verifier_identifier
                .finalize_add_watcher(add_watcher.as_bytes(), signature)
                .await?;
    
            assert!(
                verifier_identifier.watchers().unwrap().contains(wat_id)
            );

            println!("\tAdded [{}] as watcher for {} [{}]", p_id(&wat_id), name, p_id(&verifier_identifier.id()));
        }
    
        // Send witnesses to verifier's wachers
        // for wit_oobi in wit_net_oobi {
        //     let oobi = Oobi::Location(wit_oobi.clone());
        //     verifier_identifier
        //         .resolve_oobi(&oobi.clone())
        //         .await?;
        //     // Skipped assuming witnesses are already discovered by watchers by using initial_oobit parameter
        //     // verifier_identifier
        //     //     .send_oobi_to_watcher(&verifier_identifier.id().clone(), &oobi)
        //     //     .await?;
        // }
        
        // Select a random Witness as Witness for watcher
        let random_index = rand::thread_rng().gen_range(0..wit_net_id.len());

        let ask = ask_watchers_to_watch_identifiers(name, 
            to_watch, 
            // Some(wit_net_id[random_index].clone()), 
            &mut verifier_identifier, 
            &verifier_key_manager
        ).await;

        // Sending its own OOBI to the set-upped WATCHERS
        if send_oobi {
            let signer_oobi = EndRole {
                cid: verifier_identifier.id().clone(),
                role: keri_core::oobi::Role::Witness,
                eid: keri_controller::IdentifierPrefix::Basic(wit_net_id[random_index].clone()),
            };
            
            if let Err(_) = tokio::time::timeout(Duration::from_secs(60), verifier_identifier
                .send_oobi_to_watcher(
                    &verifier_identifier.id().clone(),
                    &Oobi::EndRole(signer_oobi),
                )).await {
                    println!("[{}] {} (watching) : {}", name, "Error".red(), "Timed out OOBI");
                }
        }

        match ask {
            Ok(()) => (),
            Err(error) => println!("Error in `init_identifier_with_watcher`, while calling `ask_watchers_to_watch_identifiers`: {}", 
                                                    error),
        }
    
        Ok((verifier_identifier, verifier_controller, verifier_key_manager))
    }

    #[allow(dead_code)]
    pub async fn ask_watchers_to_watch_identifiers(
        name: &str, 
        to_watch: Vec<ToWatch>,
        // oobi_wit_id: Option<BasicPrefix>, 
        verifier_identifier: &mut Identifier,
        verifier_key_manager: &CryptoBox,
    ) -> Result<(), ControllerError> {
        // Check if watchers are setup correctly
        assert!(
            verifier_identifier.watchers().unwrap().len() > 0
        );

        // Send signers oobis to verifier's watchers and query for results.
        for signer_identifier in &to_watch {
            println!("\tAsking {} [{}]'s watchers to watch [{}]", name, p_id(&verifier_identifier.id()), p_id(&signer_identifier.prefix.clone()));

            // match oobi_wit_id {
            //     Some(ref wit_id) => {
            //         let signer_oobi = EndRole {
            //             cid: signer_identifier.prefix.clone(),
            //             role: keri_core::oobi::Role::Witness,
            //             eid: keri_controller::IdentifierPrefix::Basic(wit_id.clone()),
            //         };
                    
            //         if let Err(_) = tokio::time::timeout(Duration::from_secs(60), verifier_identifier
            //             .send_oobi_to_watcher(
            //                 &verifier_identifier.id().clone(),
            //                 &Oobi::EndRole(signer_oobi),
            //             )).await {
            //                 println!("[{}] {} (watching) : {}", name, "Error".red(), "Timed out OOBI");
            //             }
            //     }

            //     None => ()
            // }
    
            assert!(verifier_identifier.get_last_establishment_event_seal().is_ok());
            
            // Query watchers about the added identifiers
            let qry_watcher = verifier_identifier.query_watchers(&signer_identifier.event_seal)?;
            for qry in qry_watcher {
                let signature = SelfSigningPrefix::Ed25519Sha512(verifier_key_manager.sign(&qry.encode()?)?);
                let query_and_signature = vec![(qry, signature)];
                // let mut q  = verifier_identifier.finalize_query(query_and_signature.clone()).await;
                let mut q = tokio::time::timeout(Duration::from_secs(30), 
                    verifier_identifier.finalize_query(query_and_signature.clone())
                ).await;

                let max_attempts = 6;
                let mut attempt = 0;
                let mut delay_ms = 0;
            
                while q.is_err() {

                    if let Err(err_msg) = q {
                        println!("[{}] {} (watching) : {}", name, "Error".yellow(), err_msg);
                    }

                    if attempt > 0 {
                        delay_ms *= 2; // Double the delay duration
                    } 

                    let max_random_delay = (delay_ms as f32 * 0.3) as u64;
                    let random_delay_ms: i64 = rand::thread_rng().gen_range(0..=max_random_delay*2) as i64 - max_random_delay as i64;
                    // Add the random delay to the current delay duration
                    delay_ms = delay_ms + random_delay_ms;

                    // Sleep for the calculated total delay duration
                    sleep(Duration::from_millis(delay_ms.try_into().unwrap())).await;

                    // q = verifier_identifier.finalize_query(query_and_signature.clone()).await;
                    q = tokio::time::timeout(Duration::from_secs(10), 
                            verifier_identifier.finalize_query(query_and_signature.clone())
                        ).await;

                    attempt += 1;
                    if attempt == 1 {
                        delay_ms = 1000; // Initial delay of 1000 millisecond
                    }
                    if attempt == max_attempts {
                        panic!("{}", "Maximum retry attempts reached. Operation failed.");
                    }
                
                }
            }
        }

        Ok(())
    }

    #[allow(dead_code)]
    pub async fn init_identifier (
        name: &str, 
        wit_net_id: &Vec<BasicPrefix>, 
        wit_net_oobi: &Vec<LocationScheme>,
        witness_threeshold: u64
    ) -> Result<(Identifier, Arc<Controller>, CryptoBox), ControllerError> {
        let (verifier_identifier, verifier_controller, verifier_key_manager) 
            = init_identifier_db_and_witnesses(name, wit_net_id, wit_net_oobi, witness_threeshold).await.unwrap();
        Ok((verifier_identifier, verifier_controller, verifier_key_manager))
    }

    #[allow(dead_code)]
    async fn init_identifier_db_and_witnesses(
        name: &str, 
        wit_net_id: &Vec<BasicPrefix>, 
        wit_net_oobi: &Vec<LocationScheme>, 
        witness_threeshold: u64

    ) -> Result<(Identifier, Arc<Controller>, CryptoBox), ControllerError>  {
        // Establish identifier
        // Setup database path and key manager.
        let verifier_database_path = Builder::new().prefix(name).tempdir().unwrap();
        let verifier_key_manager = CryptoBox::new().unwrap();
    
        // The `Controller` structure aggregates all known KEL events (across all
        // identifiers) and offers functions for retrieving them, verifying the
        // integrity of new events, and conducting signature verification.
        let verifier_controller = Arc::new(Controller::new(ControllerConfig {
            db_path: verifier_database_path.path().to_owned(),
            ..Default::default()
        })?);

        // Incept identifier.
        // The `Identifier` structure facilitates the management of the
        // Key Event Log specific to a particular identifier.
        let pk = BasicPrefix::Ed25519(verifier_key_manager.public_key());
        let npk = BasicPrefix::Ed25519(verifier_key_manager.next_public_key());

        // let x : Vec<_> = wit_net_oobi.iter().cloned().collect();

        // println!("icp_witnesses: {:?}", x);

        // Create inception event, that needs one witness receipt to be accepted.
        let icp_event = verifier_controller
            .incept(
                vec![pk],
                vec![npk],
                wit_net_oobi.iter().cloned().collect(),
                witness_threeshold //(wit_net_oobi.len() as u64)/2+1,
            )
            .await?;

        // println!("ICP EVENT ############## : {:?}", icp_event);
        let signature =
            SelfSigningPrefix::Ed25519Sha512(verifier_key_manager.sign(icp_event.as_bytes()).unwrap());

        let mut verifier_identifier =
            verifier_controller.finalize_incept(icp_event.as_bytes(), &signature)?;

        
        // The Event Seal specifies the stage of KEL at the time of signature creation.
        // This enables us to retrieve the correct public keys from KEL during verification.
        // Trying to get current actor event seal.
        let inception_event_seal = verifier_identifier.get_last_establishment_event_seal();

        // It fails because witness receipts are missing.
        assert!(matches!(
            inception_event_seal,
            Err(ControllerError::UnknownIdentifierError)
        ));

    
        // Publish event to actor's witnesses
        let max_attempts = 6;
        let mut attempt = 0;
        let mut delay_ms = 500;
        while verifier_identifier.notify_witnesses().await.is_err() {
            delay_ms *= 2; // Double the delay duration
            let max_random_delay = (delay_ms as f32 * 0.1) as u64;
            let random_delay_ms = rand::thread_rng().gen_range(0..=max_random_delay);
            // Add the random delay to the current delay duration
            delay_ms = delay_ms + random_delay_ms;
            sleep(Duration::from_millis(delay_ms)).await;
            attempt += 1;
            if attempt == max_attempts {
                panic!("{}", "(init_identifier_db_and_witnesses) Maximum retry attempts reached. Operation failed.");
            }
        }
    
        // Querying witness to get receipts
        for qry in verifier_identifier
            .query_mailbox(verifier_identifier.id(), &(wit_net_id))
            .unwrap()
        {
            let signature = SelfSigningPrefix::Ed25519Sha512(
                verifier_key_manager.sign(&qry.encode().unwrap()).unwrap(),
            );
            verifier_identifier
                .finalize_query_mailbox(vec![(qry, signature)])
                .await
                .unwrap();
        }
    
        // Check if verifying identifier was established successfully
        let inception_event_seal = verifier_identifier.get_last_establishment_event_seal();
        assert!(inception_event_seal.is_ok());
        println!("Incepted: {} [{}]", &name, p_id(&verifier_identifier.id()));

        Ok((verifier_identifier, verifier_controller, verifier_key_manager))
    }

    #[allow(dead_code)]
    pub fn p_id(p: &IdentifierPrefix) -> String {
        let s = p.to_string();
        (s[s.len() - 4..]).to_owned()
    }
    
    #[allow(dead_code)]
    pub async fn query_kel(
        name: i32,
        querier_identifier: Arc<Mutex<Identifier>>, 
        querier_key_manager: &CryptoBox,
        _queried_id: &IdentifierPrefix,
        event_seal: &EventSeal
    ) -> Result<String, ControllerError>  {
        // Query kel of signing identifier
        let queries_and_signatures: Vec<_> = querier_identifier.lock().await
            .query_watchers(&event_seal)?
            .into_iter()
            .map(|qry| {
                let signature = SelfSigningPrefix::Ed25519Sha512(
                    querier_key_manager.sign(&qry.encode().unwrap()).unwrap(),
                );
                (qry, signature)
            })
            .collect();

        let (mut q, mut err) = querier_identifier.lock().await
            .finalize_query(queries_and_signatures.clone())
            .await;
        // let mut q = tokio::time::timeout(Duration::from_secs(30), 
        // querier_identifier.finalize_query(queries_and_signatures.clone())
        // ).await;

        // Watcher might need some time to find KEL. Ask about it until it's ready.

        let max_attempts = 6;
        let mut attempt = 0;
        let mut delay_ms = 0;
                
        while !err.is_empty() || q == QueryResponse::NoUpdates {

            if !err.is_empty(){
                println!("[{}] {} (query_kel): {:?}", name, "Error".yellow(), err);
            } else {
                println!("[{}] {} (query_kel)", name, "No updates".yellow());
            }

            if attempt > 0 {
                delay_ms *= 2; // Double the delay duration
            } 

            let max_random_delay = (delay_ms as f32 * 0.1) as u64;
            let random_delay_ms = rand::thread_rng().gen_range(0..=max_random_delay);
            // Add the random delay to the current delay duration
            delay_ms = delay_ms + random_delay_ms;

            // Sleep for the calculated total delay duration
            sleep(Duration::from_millis(delay_ms)).await;


            (q, err) = querier_identifier.lock().await
                .finalize_query(queries_and_signatures.clone())
                .await;

            // q = tokio::time::timeout(Duration::from_secs(10), 
            // querier_identifier.finalize_query(queries_and_signatures.clone())
            // ).await;

            attempt += 1;
            if attempt == 1 {
                delay_ms = 1000; // Initial delay of 1000 millisecond
            }
            if attempt == max_attempts {
                println!("[{}] {}", name, "Maximum retry attempts reached. Operation failed.".red());
                return Err(ControllerError::OtherError("Cannot query KEL of provided identifier".to_owned()));
            }
        }

        // Now get expected KEL
        let kel = querier_identifier
            .lock()
            .await
            .get_kel()
            .unwrap();
        // let kel_str = String::from_utf8(kel.unwrap()).unwrap();
        // println!("{:?}", String::from_utf8(kel.unwrap()).unwrap());

        Ok(format!("{:?}", kel))
    }

    #[link(name = "c")]
    extern "C" {
        fn geteuid() -> u32;
    }

    #[allow(dead_code)]
    pub fn clear_data() {
        // Kill already running witnesses and watchers
        let euid = unsafe { geteuid() };

        let mut cmd = Command::new("pkill");
        cmd.arg("-f");
        cmd.arg("witness|watcher");
        cmd.arg("-u");
        cmd.arg(euid.to_string());
        cmd.arg("-e");
        let mut child = cmd.spawn().expect("Unable to stop running processes");
        // Wait for the command to finish executing
        let _ = child.wait();

        // Remove db folder
        cmd = Command::new("rm");
        // Add arguments to the command
        cmd.arg("-rf");
        cmd.arg("db");
        // Spawn the command asynchronously
        let mut child2 = cmd.spawn().expect("Unable to remove db folder");
        // Wait for the command to finish executing
        let _ = child2.wait();
    }

    // Function to check if a port is open
    #[allow(dead_code)]
    pub fn is_port_open(mut addr: String, port: u16) -> bool {
        // Create a socket address by combining the address and port
        if addr == "localhost" {
            addr = "127.0.0.1".to_string();
        }
        let socket_addr = format!("{}:{}", addr, port);
        match socket_addr.parse::<SocketAddr>() {
            Ok(socket_addr) => {
                // Try to connect to the socket address
                if let Ok(_) = TcpStream::connect(socket_addr) {
                    // println!("Port {} is open", port);
                    true
                } else {
                    // println!("{} {} {}", "Port".red(), port.to_string().red(), "is closed".red());
                    false
                }
            }
            Err(_) => {
                eprintln!("Invalid address: {}", addr);
                false
            }
        }
    }

    #[derive(Deserialize, Debug)]
    struct ConfigStrings {
        eid: String,
        scheme: String,
        url: String,
    }

    #[allow(dead_code)]
    pub fn parse_witness_config(ch_gov_wit_net_id : &mut Vec<BasicPrefix>, ch_gov_wit_net_oobi: &mut Vec<LocationScheme>) {
        let file = fs::File::open("config/witnessConfigs.json")
            .expect("Cannot open `config/witnessConfigs.json`");
        let reader = BufReader::new(file);

        let json : Vec<ConfigStrings> = serde_json::from_reader(reader).unwrap();

        for conf in &*json {
            let basic_prefix : BasicPrefix = conf.eid.parse().unwrap();
            ch_gov_wit_net_id.push(basic_prefix.clone());
            let oobi : LocationScheme = serde_json::from_str(&format!(
                r#"{{"eid":{:?},"scheme":"{}","url":"{}"}}"#, basic_prefix, conf.scheme, conf.url
            )).unwrap();    
            ch_gov_wit_net_oobi.push(oobi.clone());
        }
    }

    #[allow(dead_code)]
    pub fn parse_witness_config_oobi(ch_gov_wit_net_oobi: &mut Vec<Oobi>) {
        let file = fs::File::open("config/witnessConfigs.json")
            .expect("Cannot open `config/witnessConfigs.json`");
        let reader = BufReader::new(file);

        let json : Vec<ConfigStrings> = serde_json::from_reader(reader).unwrap();

        for conf in &*json {
            let basic_prefix : BasicPrefix = conf.eid.parse().unwrap();
            let lc : LocationScheme = serde_json::from_str(&format!(
                r#"{{"eid":{:?},"scheme":"{}","url":"{}"}}"#, basic_prefix, conf.scheme, conf.url
            )).unwrap();    
            ch_gov_wit_net_oobi.push(Oobi::Location(lc.clone()));
        }
    }

    #[allow(dead_code)]
    pub fn parse_watcher_config(ch_gov_wat_net_id : &mut Vec<IdentifierPrefix>, ch_gov_wat_net_oobi: &mut Vec<Oobi>) {
        let file = fs::File::open("config/watcherConfigs.json")
            .expect("Cannot open `config/watcherConfigs.json`");
        let reader = BufReader::new(file);

        let json : Vec<ConfigStrings> = serde_json::from_reader(reader).unwrap();

        for conf in &*json {
            let basic_prefix : IdentifierPrefix = conf.eid.parse().unwrap();
            ch_gov_wat_net_id.push(basic_prefix.clone());
            let oobi : Oobi = serde_json::from_str(&format!(
                r#"{{"eid":"{}","scheme":"{}","url":"{}"}}"#, basic_prefix, conf.scheme, conf.url
            )).unwrap();    
            ch_gov_wat_net_oobi.push(oobi.clone());
        }
    }

    #[allow(dead_code)]
    pub fn parse_watcher_config_oobi(ch_gov_wat_net_oobi: &mut Vec<Oobi>) {
        let file = fs::File::open("config/watcherConfigs.json")
            .expect("Cannot open `config/watcherConfigs.json`");
        let reader = BufReader::new(file);

        let json : Vec<ConfigStrings> = serde_json::from_reader(reader).unwrap();

        for conf in &*json {
            let basic_prefix : IdentifierPrefix = conf.eid.parse().unwrap();
            let oobi : Oobi = serde_json::from_str(&format!(
                r#"{{"eid":"{}","scheme":"{}","url":"{}"}}"#, basic_prefix, conf.scheme, conf.url
            )).unwrap();    
            ch_gov_wat_net_oobi.push(oobi.clone());
        }
    }

    pub fn handle_connection<T>(mut stream: TcpStream) -> Result<T, serde_json::Error> 
    where T : DeserializeOwned + Debug,
    {
        let mut buf_reader = BufReader::new(&mut stream);
        let mut http_request = Vec::new();
        let mut headers = Vec::new();
    
        // Read the request headers
        for line in buf_reader.by_ref().lines() {
            let mut _line_string = String::new();
            match line {
                Ok(l) => _line_string = l,
                Err(_err) => return Err(serde_json::Error::custom("Invalid Buffer"))
            }
            if _line_string.is_empty() {
                break;
            }
            headers.push(_line_string.clone());
            http_request.push(_line_string);
        }
    
        // println!("Request Headers: {:#?}", headers);
    
        // Determine the content length
        let content_length = headers.iter()
            .find(|&line| line.starts_with("content-length:")) // reqwest send it withouth capital letters
            .and_then(|line| line.split(':').nth(1))
            .and_then(|len| usize::from_str(len.trim()).ok())
            .unwrap_or(0);
    
        // Read the request body
        let mut body = vec![0; content_length];
        buf_reader.read_exact(&mut body).unwrap();
    
        // println!("Request Body: {:?}", String::from_utf8_lossy(&body));
    
        // Parse the JSON body
        let message: serde_json::Result<T> = serde_json::from_slice(&body);
    
        // Send a response
        let response = "HTTP/1.1 200 OK\r\n\r\n";
        match stream.write_all(response.as_bytes()) {
            Ok(_) => (),
            Err(err) => eprintln!("Error sending a response (handle_connection): {}", err)
        }

        return message;
    }

    #[allow(dead_code)]
    pub fn wait_for_http_msg<T>(listener : Arc<TcpListener>) -> Option<T>
    where T : DeserializeOwned + Debug,
    {
        for stream in listener.incoming() {
            let stream: TcpStream = stream.unwrap();
            let msg : Result<T, serde_json::Error> = handle_connection(stream);
            match msg {
                Ok(message) => return Some(message),
                Err(e) => println!("{} {:?}", "Error while deserializing http message:".red(), e)
            };
        }
        None
    }

    #[allow(dead_code)]
    pub fn get_current_formatted_datetime() -> String {
        Utc::now().format("%Y-%m-%d %H:%M:%S").to_string()
    }

    #[allow(dead_code)]
    pub fn serialize_json_and_write<T> (data : T, filename : String)
    where T : Serialize + Debug,
    {
        // Serialize to JSON
        let json_data = serde_json::to_string_pretty(&data).unwrap();
        // Write JSON to a file
        let mut file = File::create(filename).unwrap();
        file.write_all(json_data.as_bytes()).unwrap();
    }

    #[allow(dead_code)]
    pub async fn rotate(
        name: String,
        id: Arc<Mutex<Identifier>>, 
        km: &mut CryptoBox,
        wit_net_id: Vec<BasicPrefix>,
        s_r: u64,
        s_w: u64,
        witness_to_add: Vec<LocationScheme>,
        witness_to_remove: Vec<BasicPrefix>
    ) {
        println!("[{}] Starts Rotation", name);
        km.rotate().unwrap();
        let pk = BasicPrefix::Ed25519(km.public_key());
        let npk = BasicPrefix::Ed25519(km.next_public_key());
    
        let rotation_event = id.lock().await
            .rotate(vec![pk], vec![npk], s_w, witness_to_add, witness_to_remove, s_r)
            .await.unwrap();
    
        let signature = SelfSigningPrefix::Ed25519Sha512(km.sign(rotation_event.as_bytes()).unwrap());
        id.lock().await
            .finalize_rotate(rotation_event.as_bytes(), signature)
            .await.unwrap();
    
        // Publish event to actor's witnesses
        id.lock().await.notify_witnesses().await.unwrap();
    
        // Querying witnesses to get receipts
        let issuer_id_id = id.lock().await.id().clone();
        let iterate = id.lock().await
            .query_mailbox(
                &issuer_id_id,
                &wit_net_id,
            )
            .unwrap();
        for qry in iterate
        {
            let signature =
                SelfSigningPrefix::Ed25519Sha512(km.sign(&qry.encode().unwrap()).unwrap());
                id.lock().await
                    .finalize_query_mailbox(vec![(qry, signature)])
                    .await
                    .unwrap();
        }
        println!("[{}] Ends Rotation", name);
    }

    #[allow(dead_code)]
    pub async fn init_tel(
        name: String,
        id: Arc<Mutex<Identifier>>, 
        km: &mut CryptoBox,
        wit_net_id: Vec<BasicPrefix>
    ) -> IdentifierPrefix
    {
        let id_id = id.lock().await.id().clone();
        println!("Incepting TEL for {} [{}]", name, p_id(&id_id));
        // Incept registry. It'll generate ixn (registry inception event, interaction event) that need to be signed.
        let (tel_id, vcp_ixn) = id.lock().await.incept_registry().unwrap();

        // Sign interaction message for registry inception, and add it to the KEL (anchoring)
        // And notify witnesses
        let signature = SelfSigningPrefix::Ed25519Sha512(km.sign(&vcp_ixn).unwrap());
        id.lock().await.finalize_incept_registry(&vcp_ixn, signature).await.unwrap();
        id.lock().await.notify_witnesses().await.unwrap();
        let queries = id.lock().await.query_mailbox(&id_id, &wit_net_id).unwrap();
        for qry in queries {
            let signature = SelfSigningPrefix::Ed25519Sha512(km.sign(&qry.encode().unwrap()).unwrap());
            let _act = id.lock().await.finalize_query_mailbox(vec![(qry, signature)]).await.unwrap();
        }

        println!("\tIncepted TEL [{}] of {} [{}]", p_id(&tel_id), name, p_id(&id_id));
        tel_id
    }

    #[allow(dead_code)]
    pub async fn issue_private_acdc(
        issuer_name: String,
        issuer_id: Arc<Mutex<Identifier>>, 
        issuer_km: &mut CryptoBox,
        issuer_wit_net_id: Vec<BasicPrefix>,
        issuer_registry_id: IdentifierPrefix,
        attributes: InlineAttributes,
        issuee_id: Option<IdentifierPrefix>
    ) -> IdentifierPrefix
    { 
        let issuer_id_id = issuer_id.lock().await.id().clone();
        let acdc_attestation: Attestation = match issuee_id {
            // The ACDC is targeted
            Some(target_id) => {
                Attestation::new_private_targeted(
                    &issuer_id_id.to_string(),
                    &target_id.to_string(),
                    issuer_registry_id.to_string(),
                    HashFunction::from(HashFunctionCode::Blake3_256)
                        .derive(&[0; 30])
                        .to_string(),
                        attributes,
                )
            },

            // The ADCD is untargeted
            None => {
                Attestation::new_private_untargeted(
                    &issuer_id.lock().await.id().to_string(), 
                    issuer_registry_id.to_string(), 
                    HashFunction::from(HashFunctionCode::Blake3_256)
                        .derive(&[0; 30])
                        .to_string(), 
                    attributes)
            }
        };

        let derivation_data =
        acdc_attestation.derivation_data(&HashFunctionCode::Blake3_256, &SerializationFormats::JSON);
        assert!(acdc_attestation.digest.clone().unwrap().verify_binding(&derivation_data));

        let credential = acdc_attestation
                        .encode(&HashFunctionCode::Blake3_256, &SerializationFormats::JSON)
                        .unwrap();
        // let credential_string = String::from_utf8(credential.clone()).unwrap();
        let credential_said =
            HashFunction::from(HashFunctionCode::Blake3_256).derive(&credential);
        
        // Issue credential. It'll generate ixn message, that needs to be signed and sent to the witnesses
        let (vc_hash, iss_ixn) = issuer_id.lock().await.issue(credential_said.clone()).unwrap();
        let sai: said::SelfAddressingIdentifier = match &vc_hash {
            IdentifierPrefix::SelfAddressing(sai) => sai.clone(),
            _ => unreachable!(),
        };

        let signature = SelfSigningPrefix::Ed25519Sha512(issuer_km.sign(&iss_ixn).unwrap());
        issuer_id.lock().await.finalize_issue(&iss_ixn, signature).await.unwrap();
        issuer_id.lock().await.notify_witnesses().await.unwrap();
        let queries = issuer_id.lock().await.query_mailbox(&issuer_id_id, &issuer_wit_net_id).unwrap();
        for qry in queries {
            let signature = SelfSigningPrefix::Ed25519Sha512(issuer_km.sign(&qry.encode().unwrap()).unwrap());
            let _act = issuer_id.lock().await.finalize_query_mailbox(vec![(qry, signature)]).await.unwrap();
        }

        let vc_state = issuer_id.lock().await.find_vc_state(&sai).unwrap();
        assert!(matches!(vc_state, Some(TelState::Issued(_))));

        let issued_value = match &vc_state {
            Some(TelState::Issued(sai)) => {
                IdentifierPrefix::SelfAddressing(sai.clone())
            },
            Some(_) => todo!(),
            None => todo!()
        };

        // Now publish corresponding tel events to backers. Verifier can find them there.
        issuer_id.lock().await.notify_backers().await.unwrap();

        println!("{} [{}] - Issues message [{:?}]", issuer_name, p_id(&issuer_id.lock().await.id()), p_id(&issued_value));

        vc_hash
    }

    #[allow(dead_code)]
    pub async fn verify_credential(
        verifier_id: Arc<Mutex<Identifier>>, 
        verifier_km: &mut CryptoBox,
        issuer_id: IdentifierPrefix,
        issuer_registry_id: IdentifierPrefix,
        credential_event_seal: EventSeal,
        credential_hash: IdentifierPrefix
    ) -> Option<TelState>
    { 
        let sai: said::SelfAddressingIdentifier = match &credential_hash {
            IdentifierPrefix::SelfAddressing(sai) => sai.clone(),
            _ => unreachable!(),
        };
    
        // Try to verify it
        // verifier needs to have issuer's KEL to accept TEL events. Query it's
        // watcher for it.
        // `last_event_seal`, `registry_id` and `vc_hash` should be provided to
        // verifier by issuer.
        let _kel_result = query_kel(1, verifier_id.clone(), &verifier_km, &issuer_id.clone(), &credential_event_seal).await.unwrap();
        // println!("KEL is: {:?}", kel_result);

        // Query witness about issuer's TEL.
        let qry = verifier_id.lock().await.query_tel(issuer_registry_id, credential_hash.clone()).unwrap();
        let signature =
            SelfSigningPrefix::Ed25519Sha512(verifier_km.sign(&qry.encode().unwrap()).unwrap());
        verifier_id
            .lock()
            .await
            .finalize_query_tel(qry, signature)
            .await
            .unwrap();
        
        // Return the non-None state of credential
        verifier_id.lock().await.find_vc_state(&sai).unwrap()
    }
    
}