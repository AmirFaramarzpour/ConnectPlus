# ConnectPlus [Free-Version]

ConnectPlus is a robust server framework that effectively handles the management of HTTP and Socket servers, user administration, and performance monitoring, all in a streamlined manner. It utilizes `customtkinter` for its graphical user interface, offering a visually appealing and user-friendly experience.
## Features
- **HTTP and Socket Server Configuration**: Start, stop, and configure both HTTP and Socket servers with ease.
- **User Management**: Add, remove, and list users with a simple GUI.
- **Performance Monitoring**: Real-time monitoring of system resources to ensure optimal performance.

For additional advanced features, consider upgrading to [ConnectPlus-Pro](https://github.com/AmirFaramarzpour/ConnectPlus-Pro.git), which includes:
1. Integration with OpenAI GPT-4o-mini API for as an assistant.
2. Complete UI improvement for a better user experience.
3. Bug fixes for smoother performance.

## Table of Contents
- [Installation](#installation)
- [Usage](#usage)
- [Imports and Dependencies](#imports-and-dependencies)
- [Code Structure](#code-structure)
- [License](#license)

## Installation
To install and run ConnectPlus, follow these steps:

1. **Clone the Repository**:
    ```bash
    git clone https://github.com/AmirFaramarzpour/ConnectPlus.git
    cd ConnectPlus
    ```

2. **Install Dependencies**:
    Make sure you have `pip` installed. Run the following command to install the required packages:
    ```bash
    pip install -r requirements.txt
    ```

3. **Run the Application**:
    Start the server side application with:
    ```bash
    python server.py
    ```
   Start the client side application with:
    ```bash
    python client.py
    ```

## Usage
1. **Server Configuration**:
    - Configure and start/stop the HTTP and Socket servers using the provided GUI.
    - Input the desired port numbers and shared directories for the servers.

2. **User Management**:
    - Add new users by entering a username and password.
    - Remove users from the system.
    - View the list of current users.

3. **Performance Monitoring**:
    - Monitor system resources such as CPU and memory usage in real-time.

## Imports and Dependencies
ConnectPlus uses several Python libraries to function effectively:
- `socket`
- `threading`
- `http.server`
- `socketserver`
- `customtkinter`
- `base64`
- `tkinter`
- `filedialog`
- `qrcode`
- `PIL`
- `psutil`
- `datetime`
- `os`
- `scrolledtext`

Make sure to install these libraries using `pip install -r requirements.txt`.

## License
This project is licensed under the MIT License.

## Contact
For any questions or feedback, please contact us at amirfaramarzpour@outlook.com.
