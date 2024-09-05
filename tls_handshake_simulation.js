const readline = require('readline');

const rl = readline.createInterface({
    input: process.stdin,
    output: process.stdout
});

const tlsVersions = [
    { name: "TLS 1.0", value: 10 },
    { name: "TLS 1.1", value: 11 },
    { name: "TLS 1.2", value: 12 },
    { name: "TLS 1.3", value: 13 },
];

const cipherSuites = [
    { name: "AES-128-GCM", value: 1 },
    { name: "AES-256-GCM", value: 2 },
    { name: "CHACHA20-POLY1305", value: 3 },
    { name: "DES-CBC3-SHA", value: 4 }, 
];

// Function to get user input
function getUserChoice(options, entity) {
    return new Promise((resolve) => {
        console.log(`\nSelect supported options for ${entity}:`);
        options.forEach((option, index) => {
            console.log(`${index + 1}. ${option.name}`);
        });

        rl.question("Enter your choice: ", (answer) => {
            const choice = parseInt(answer) - 1;
            if (choice >= 0 && choice < options.length) {
                resolve(options[choice].value);
            } else {
                console.log("Invalid choice. Please try again.");
                resolve(getUserChoice(options, entity));
            }
        });
    });
}

// Function to negotiate TLS version
function negotiateTLSVersion(clientVersion, serverVersion) {
    return Math.min(clientVersion, serverVersion);
}

// Function to select cipher suite
function selectCipherSuite(clientSuite, serverSuite) {
    if (clientSuite === serverSuite) {
        return clientSuite;
    } else {
        return -1; // No common cipher suite
    }
}

// (Simplified) Diffie-Hellman key exchange
function diffieHellmanKeyExchange() {
    // This is a VERY simplified representation for demonstration purposes
    const clientSecret = 5; 
    const serverSecret = 7;
    const prime = 11;
    const generator = 2;

    const clientPublic = Math.pow(generator, clientSecret) % prime;
    const serverPublic = Math.pow(generator, serverSecret) % prime;

    const sharedSecret = Math.pow(serverPublic, clientSecret) % prime;

    return sharedSecret;
}

// Main execution
async function main() {
    const clientTLSVersion = await getUserChoice(tlsVersions, "Client");
    const serverTLSVersion = await getUserChoice(tlsVersions, "Server");
    const clientCipherSuite = await getUserChoice(cipherSuites, "Client");
    const serverCipherSuite = await getUserChoice(cipherSuites, "Server");

    const negotiatedTLSVersion = negotiateTLSVersion(clientTLSVersion, serverTLSVersion);
    const selectedCipherSuite = selectCipherSuite(clientCipherSuite, serverCipherSuite);
    const sharedKey = diffieHellmanKeyExchange();

    if (negotiatedTLSVersion > 0 && selectedCipherSuite > 0) {
        console.log("\nHandshake Successful!");
        console.log("Negotiated TLS Version: TLS " + (negotiatedTLSVersion / 10).toFixed(1));
        console.log("Selected Cipher Suite: " + cipherSuites[selectedCipherSuite - 1].name);
        console.log("Shared Secret Key: " + sharedKey);
    } else {
        console.log("\nHandshake Failed!");
        if (negotiatedTLSVersion <= 0) {
            console.log("Error: No common TLS version found.");
        }
        if (selectedCipherSuite <= 0) {
            console.log("Error: No common cipher suite found.");
        }
    }

    rl.close();
}

// Start the simulation
main();