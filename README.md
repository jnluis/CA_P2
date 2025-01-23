# Applied Cryptography

### Academic Year: 2024/25

### Grade: 17.7

## Project 2 - Selective Identity Disclosure (SID)

This project implements a Selective Identity Disclosure (SID) system that allows users to securely share specific identity attributes from their Digital Citizen Card (DCC) while maintaining privacy and proving ownership. The system enables users to choose which personal information they want to disclose, ensuring that only necessary data is shared with validators.

--- 
### Implementation

To run this project, you should follow this steps:

```shell
python3 -m venv venv
source venv/bin/activate
pip3 install -r requirements.txt
```

If you want to use the Portuguese Citizen Card (CC), the following steps are also necessary:
1. Install [Autenticação.gov](https://www.autenticacao.gov.pt/cc-aplicacao) on your system;
2. If you are on Linux, you may also need **pcscd**;

For this project, 4 applications were developed:

1. To use ```req_dcc```, start with:
    ```shell
    python3 gen_dcc.py
    ```

    Then, open a split-terminal and run:

    ```shell
    python3 req_dcc.py
    ```

2. To use ```gen_min_DCC.py```, run:
    ```shell
    python3 gen_min_DCC.py DCC.json owner_private_key.pem
    ```

    If you want to sign with Citizen Card (you need to know the Authentication PIN for the used CC), do:

    ```shell
    python3 gen_min_DCC.py DCC.json
    ```

3. To use ```check_dcc.py```, run:
    ```shell
    python3 check_dcc.py min_DCC.json 
    ```





#### Project done by [@jnluis](https://github.com/jnluis) and [@ricardoquintaneiro](https://github.com/ricardoquintaneiro)