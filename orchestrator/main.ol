from .keycloak.keycloak import Keycloak
from file import File
from .blockchainAPI.CAClient import CAClient
from .blockchainAPI.blockchainClient import BlockchainAPI
from console import Console
from string_utils import StringUtils

type ErrorMessage {
    error: string
    errorDescription: string
}

interface OrchestratorInterface {
    RequestResponse: 
        executeTransaction(TransactionRequest)(undefined) throws Unauthorized( ErrorMessage ), UserRegistrationFailed, TransactionFailed //TODO define proper response type
} 

type TransactionRequest {
    accessToken: string
    transaction {
        type: string( enum(["query", "invoke"]) )
        transaction {
            chaincodeid: string( enum(["dt4hCC"]) )
            channelid: string( enum(["dt4h"]) )
            function: string( enum(["LogQuery", "GetUserHistory", "GetMyHistory", "WhoAmI", "PrivacyBudgetContract:WhoAmI"]) )
            args[0, *]: string
        }
    }
}

service Orchestrator {
    embed Keycloak as Keycloak
    embed File as File
    embed CAClient as CAClient
    embed BlockchainAPI as BlockchainAPI
    embed StringUtils as StringUtils
    embed Console as Console

    execution: concurrent

    inputPort ip {
        location: "socket://localhost:7000"
        protocol: https {
            debug = true
            contentType = "json"
            format = "json"
            compression = false 
            method = "POST"
            response << {
                headers.("Access-Control-Allow-Origin") = "*"
                headers.("Access-Control-Allow-Methods") = "GET, POST, OPTIONS"
                headers.("Access-Control-Allow-Headers") = "Authorization, Content-Type"
            }
            ssl << {
                protocol = "TLSv1.2"
                keyStoreFormat = "PKCS12"
                keyStore = "./certs/keystore.p12"
                keyStorePassword = "fabrero"
            }
            osc.executeTransaction << {
                statusCodes << {
                    Unauthorized = 401
                    UserRegistrationFailed = 500
                    TransactionFailed = 500
                }
            }
        }
        interfaces: OrchestratorInterface
    }

    init {
        println@Console("Orchestrator service started")()
    }

	main {
       [executeTransaction(transactionReq)(transactionResponse) {
            scope (getUserData) {
                install( Unauthorized => 
                    println@Console("Unauthorized access token")()
                    throw( Unauthorized, { error = "Unauthorized", errorDescription = "Access token is invalid or expired" } )
                )
                getUserData@Keycloak(transactionReq.accessToken)(userInfo)
            
            // This three lines of code for DEMO purposes only, to predefine user attributes
            // userInfo.attributes.institution = "bsc"
            // userInfo.attributes.family_name = "Tsoukala"
            // userInfo.attributes.given_name = "Chara"
                scope (checkUserRegistration) {
                    
                    install( 
                        NotRegistered => {
                            println@Console("User is not registered in the network, registering...")()
                            createUser@CAClient(userInfo)(registerUserResponse)
                            userInfo.attributes.bcsecret = registerUserResponse.secret
                            updateUserData@Keycloak({ token = transactionReq.accessToken, attributes << userInfo.attributes })(success)
                        }
                    )

                    if (!is_defined(userInfo.attributes.bcsecret) || userInfo.attributes.bcsecret == "") {
                        throw( NotRegistered )
                    } 
                }
            }
            scope (executeTransaction) 
            {
                executeTranReq << {
                    enrollmentId = userInfo.email
                    secret = userInfo.attributes.bcsecret
                    type = transactionReq.transaction.type
                    institution = userInfo.attributes.institution 
                    transaction << transactionReq.transaction.transaction
                }
                executeTransaction@BlockchainAPI(executeTranReq)(transactionResponse)
            }   
            
            // if (!is_defined(userInfo.attributes.bcsecret) || userInfo.attributes.bcsecret == "") {
            //     createUser@CAClient(userInfo)(registerUserResponse)
            //     if (registerUserResponse.success) {
            //         userInfo.attributes.bcsecret = registerUserResponse.secret
                    
            //         updateUserData@Keycloak({ token = transactionReq.accessToken, attributes << userInfo.attributes })(success)
            //     } else {
            //         // handle registration failure
            //         println@Console("User registration failed")()
            //     }
            //     executeTranReq << {
            //         enrollmentId = userInfo.email
            //         secret = userInfo.attributes.bcsecret
            //         type = transactionReq.transaction.type
            //         institution = userInfo.attributes.institution 
            //         transaction << transactionReq.transaction.transaction
            //     }
            //     executeTransaction@BlockchainAPI(executeTranReq)(transactionResponse)
            // } else {
            //     executeTranReq << {
            //         enrollmentId = userInfo.email
            //         secret = userInfo.attributes.bcsecret
            //         type = transactionReq.transaction.type
            //         institution = userInfo.attributes.institution 
            //         transaction << transactionReq.transaction.transaction
            //     }
            //     executeTransaction@BlockchainAPI(executeTranReq)(transactionResponse)
            // }
            
            
            println@Console("Transaction executed")()
            valueToPrettyString@StringUtils(transactionResponse)(responseStr)
            println@Console(responseStr)()
       }]
	}
}

