![Logo](assets/logo.png)

A simple bot that automatically redirects Post.at shipments to your doorstep instead of distant pickup stations.

## What it does

Post.at often claims you're never home and sends packages to pickup stations far away.

You can set a preference to have them delivered to your door, but it only works if you do it for each shipment individually.

## Features

- Automatic shipment redirection
- Simple configuration
- Runs quietly in the background

## Installation

1. **Clone the repository**:
   ```bash
   git clone https://github.com/anditv21/FinallyAtYourDoorCLI.git
   cd FinallyAtYourDoorCLI
   ```

2. **Install dependencies**:
   ```bash
   pip install aiohttp colorama
   ```

3. **Create configuration**:
   Create a `config.json` file in the project directory:
   ```json
   {
     "email": "your.email@example.com",
     "password": "your_password"
   }
   ```

## Usage

Run the bot with:
```bash
python main.py
```

The bot will continuously check for shipments that need redirection and handle them automatically.

## Configuration

The `config.json` file stores your login credentials. Tokens are saved automatically after the first run.

## License

[MIT License](LICENSE)

---

Developed with 💖for a better postal experience