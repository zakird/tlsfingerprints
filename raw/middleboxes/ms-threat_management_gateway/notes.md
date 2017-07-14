# Notes
* Middle-box
    * Fully patched Win-Server 2008R2
        * Requirement of TMG
    * Enterprise Evaluation edition
        * [Download link](https://www.microsoft.com/en-us/download/details.aspx?id=14238)
    * ForeFront TMG 7.0.7734.100
* Client
    * Fully patched Win7
* Endpoint
    * echo-hello.aaspring-test.com
        * Used IOT force fall-back connection
        * Running openssl s_server
            * Can not complete connection to endpoint b/c Client Hello lacks
                compression method
    * echo-header.aaspring-test.com
        * Ran 2x IOT gather 1st visit and 2nd visit headers
        * Running custom python app
