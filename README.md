# sphincsplus GUI Tool
This is a simple graphical user interface (GUI) for the [PySPX](https://github.com/sphincs/pyspx) [SPHINCS+](https://github.com/sphincs/sphincsplus) (*the post-quantum digital signature scheme*) implementation using Python `pyspx` and `tkinter`.

## Features
* Generate SPHINCS+ keypair using selectable variants (e.g. `shake_128f`, `sha2_192s`, etc.)
* view seed, keys and their lengths
* Upload and view the plaintext message
* Sign the message using the generated keypair
* Save the digital signature to file
* Upload the message and saved signature to verify the sign is VALID or INVALID
* Reset the application to select a different variant and restart the process

## Installation and Usage
### Prerequisites (Ubuntu)
* before running  this GUI, make sure you have  OpenSSl  development libraries, Python 3.9 and later and tkinter package:

```bash
sudo apt update
sudo apt install libssl-dev build-essential
sudo apt install python3-tk
```
### Make Virtual Environment and Setup pyspx package
* To make virtual enviroment:
```bash
python3 -m venv sphincs_env
source sphincs_env/bin/activate
```
* Installing `pyspx` (Python binding for **SPHINCS+**) that is avalable in
[PySPX](https://pypi.org/project/PySPX/):
```Bash
pip install pyspx
```
Or you can install python dependencies
```bash
pip install -r requirements.txt
```
### Run the GUI
```bash
python3 gui_sphincs.py
```
#### Workflow
1. Select a "*SPHINCS+ Variant*" from the dropdown menu.

![Main GUI](/assets/screenshot_main.png)

2. Click "*Generate Keypair*" to create a new keypair by using a random seed.
3. Click "*Upload Message*" and select a plaintext `.txt` file to be signed [Sample of Message](/assets/sample_message.txt).
4. Click "*Sign Message*" to digitally sign the message.
5. Click "*Save Signature*" to save the signature to a `.sig` file. 
6. Click "*Verify Signature*" to validate the uploaded message and signature.

![Verification Window](/assets/verification_window.png)

7. Click "*Reset*" to start over and choose another variant.

## Notes
* Each varient of SPHINCS+ has different seed/key/signature lengths.
* The application restricts each process to a single run per variant to avoid confusion.
* The random seed is generated using Python's `os.urandom()`.
* This GUI uses the `pyspx` Python binding for SPHINCS+.
* If you encounter any OpenSSl or compilation issues, verify that `libssl-dev` is installed on your system.
 
 

