# ECDH Key Exchange

This project demonstrates how to use Elliptic Curve Diffie-Hellman (ECDH) key exchange to securely generate a shared secret between two parties and use that secret for AES encryption and decryption of a message.


## How to Use
To use this repository, follow these steps:

1. __Clone the Repository:__ Clone this repository to your local machine using

    ```git clone https://github.com/simplediss/Elliptic-Curve-Diffie-Hellman.git``` .

2. Optional: __Create a Virtual Environment:__ Make sure you have `Python3` installed on your machine. It's recommended to use a virtual environment to manage dependencies.
    * Navigating to the project directory.
    * Create a virtual environment using

         ```python -m venv .venv```

        ```source .venv/bin/activate```
3. __Install Dependencies:__ Install the project dependencies by running

    ```pip install -r requirements.txt```

4. __Run__ the main script (ecdh.py):

     ```python ecdh.py```

5. To run the tests:

     ```python tests.py```