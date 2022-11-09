# xApp Repository Function (XRF) for OpenAuthorization 2.0 Enablement in Linux Foundation's reference RAN Intelligent Controller
The source code of the submission to INFOCOM 2023.

## Summary of the threat model
The initial makings of an OAuth2.0 server to be integrated into the LF RIC in the future for enabling authentication between select xApps. 

The goal of this project is address the threat model given below.

![Alt text](thrmdlxrf.png?raw=true)

The scenario is showing that a functionality split has been applied to the 5G RAN protocol stack. As a result of this, the first three layers of the radio stack are implemented closer to the fronthaul in the DU while the upper two layers are closer to the backhaul inside the CU. Both the DU and CU are softwarized platforms deployed at micro-datacentres, made up of COTS hardware, in the edge network. The O-RAN near-real time RIC is deployed at the same hierarchy as the DU and CU given that the xApps will subscribe information from various radio protocol layers. The majority of the 5G core components, NFV MANO platform as well as the non-real time RIC, are deployed in the central cloud.  

The primary type of adversary is the MVNO N, who is allowed to submit onboarding requests to the management infrastructure of the 5G system. This allows them to onboard their own xAppN onto the near-real time RIC platform. xAppN is cohabiting with xApps from other MVNOs and using an open message router to exchange messages with them. Without any authentication and authorization mechanism to oversee the exchange of messages between xApps, this adversary can gain access to the message exchange loop between xApp1 and xApp2.

**Attack Vector:**
  - MVNO submits new xApp request to the MANO.
  - Resources are allocated for the xApp and the request is forwarded to the near-RT RIC
  - xApp is onboarded.
  - xApp interferes with the communication of other xApps by utilizing existing subscription IDs, bypassing authorization and authentication in intra-RIC communication. 

**Case Study:**
A scenario is formulated to describe the types of attacks that an attacker can carry out. xApp1 is subscribed to receive RLC and MAC layer information from the DU. This information is forwarded to xApp2 where various real-time load balancing decisions are made and traffic patterns are adjusted. Finally these decisions are relayed back to xApp1 for execution. In such a scenario, the attacker can carry out the following attacks.
    - *Eavesdropping*: on sensitive real-time decisions regarding user device operations. 
    - *Faulty injections*: to change either the incoming data to be used by xApp2 for decision making or outgoing data to xApp1 for execution to alter the ultimate behaviour of the system. 
    
## Testing on baremetal
- 1) Use build_script.sh to build both XRF server and client separately.
- 2) Use setenv.sh to set the required environmental variables on baremetal for local debugging.

## Refactoring Status
 - :heavy_check_mark: - InitAuth
 - :x: - Registration
 - :x: - Discovery
 - >> Won't refactor registration and discovery since they are not security protocol modules
 - :heavy_check_mark: - AccessTokReq
 - >> Currently there is a redundancy in double token decoding on both refactored and main module since main module needs to retreive public key from JWKS unordered_map
 - :heavy_check_mark: - RemoteIntro
 - :x: - JWKSdecode
 - >> Won't refactor JWKS standalone
 - :heavy_check_mark: - All token handlers {AccesTokReq + JWKSHandle + RemTokIntro}
## Refactored and Normal Images
- 1) XRF Server - InitAuth Only: tolgaomeratalay/xrfserver:auth_extv2
- 2) XRF Server - InitAuth + AccessTokReq: tolgaomeratalay/xrfserver:auth_tokreq_extv1
- 3) XRF Server - InitAuth + AccessTokReq + RemoteIntro: tolgaomeratalay/xrfserver:auth_tokreq_tokremextv1
- 4) XRF Server - InitAuth + AllTokenHandling: tolgaomeratalay/xrfserver:auth_tokreq_tokallextv1
- 5) XRF Send Client (1 connection) - Generic: tolgaomeratalay/xrfclient:senderv1
- 6) XRF Send Client (10 connections) - Generic: tolgaomeratalay/xrfclient:senderv2
- 7) XRF Recv Client - Generic: tolgaomeratalay/xrfclient:recvclientv4
- 8) InitAuthModule: tolgaomeratalay/xrfsauth:v1
- 9) AccessTokReqModule: tolgaomeratalay/xrfstokreq:v1
- 10) RemoteIntroModule: tolgaomeratalay/xrfstokrem:v2
- 11) Alltokenhandler: tolgaomeratalay/xrfstokall:v1

## Images for the Experiments
### No Isolation
- XRF Server - tolgaomeratalay/xrfserver:original_v1
- XRF Client Receiver - tolgaomeratalay/xrfclient:recvclientv4
- XRF Client Sender - tolgaomeratalay/xrfclient:senderv1
### InitAuth Only
- XRF Server - tolgaomeratalay/xrfserver:initauth_only_v1
- External Module - build from source
- XRF Client Receiver - tolgaomeratalay/xrfclient:recvclientv4
- XRF Client Sender - tolgaomeratalay/xrfclient:senderv1
### TokenGeneration Only
- XRF Server - tolgaomeratalay/xrfserver:tokgen_only_v1
- External Module - build from source
- XRF Client Receiver - tolgaomeratalay/xrfclient:recvclientv4
- XRF Client Sender - tolgaomeratalay/xrfclient:senderv1
### TokenRemoteIntro Only
- XRF Server - tolgaomeratalay/xrfserver:tokrem_only_v1
- External Module - build from source
- XRF Client Receiver - tolgaomeratalay/xrfclient:recvclientv4
### TokenAll only
- xrf server - tolgaomeratalay/xrfserver:tokall_only_v1
- external module - build from source
- xrf client receiver - tolgaomeratalay/xrfclient:recvclientv4
- xrf client sender - tolgaomeratalay/xrfclient:senderv1
### InitAuth + TokenAll Only
- XRF Server - tolgaomeratalay/xrfserver:initauth_tokall_v1
- External Module - build from source
- XRF Client Receiver - tolgaomeratalay/xrfclient:recvclientv4
- XRF Client Sender - tolgaomeratalay/xrfclient:senderv1
- >> For switching between remote token introspection and JWKS, change the "method" env variable in the xrfclient:sender deployment file (method=0--JWKS, method=1--RemoteIntro)
### {InitAuth + TokenAll} inside same Gramine-SGX
- XRF Server - tolgaomeratalay/xrfserver:allisov1
- External Module - build from source
- XRF Client Receiver - tolgaomeratalay/xrfclient:recvclientv4
- XRF Client Sender - tolgaomeratalay/xrfclient:senderv1
- >> For switching between remote token introspection and JWKS, change the "method" env variable in the xrfclient:sender deployment file (method=0--JWKS, method=1--RemoteIntro)


