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

function clientHello(clientTLSVersion, clientCipherSuite) {
    console.log("\nClient Hello:");
    console.log(`Supported TLS Version: TLS ${(clientTLSVersion / 10).toFixed(1)}`);
    console.log(`Proposed Cipher Suite: ${cipherSuites.find(suite => suite.value === clientCipherSuite).name}`);
    return { clientTLSVersion, clientCipherSuite };
}

function serverHello(serverTLSVersion, serverCipherSuite, clientHello) {
    const negotiatedTLSVersion = Math.min(clientHello.clientTLSVersion, serverTLSVersion);
    const selectedCipherSuite = clientHello.clientCipherSuite === serverCipherSuite ? serverCipherSuite : -1;

    console.log("\nServer Hello:");
    console.log(`Negotiated TLS Version: TLS ${(negotiatedTLSVersion / 10).toFixed(1)}`);
    console.log(`Selected Cipher Suite: ${selectedCipherSuite > 0 ? cipherSuites.find(suite => suite.value === selectedCipherSuite).name : 'No common cipher suite'}`);

    return { negotiatedTLSVersion, selectedCipherSuite };
}

function diffieHellmanKeyExchange() {
    const clientSecret = 5; 
    const serverSecret = 7;
    const prime = 11;
    const generator = 2;

    const clientPublic = Math.pow(generator, clientSecret) % prime;
    const serverPublic = Math.pow(generator, serverSecret) % prime;

    const sharedSecret = Math.pow(serverPublic, clientSecret) % prime;

    return sharedSecret;
}

async function main() {
    const clientTLSVersion = await getUserChoice(tlsVersions, "Client");
    const clientCipherSuite = await getUserChoice(cipherSuites, "Client");

    const clientHelloMessage = clientHello(clientTLSVersion, clientCipherSuite);

    const serverTLSVersion = await getUserChoice(tlsVersions, "Server");
    const serverCipherSuite = await getUserChoice(cipherSuites, "Server");

    const serverHelloResponse = serverHello(serverTLSVersion, serverCipherSuite, clientHelloMessage);

    if (serverHelloResponse.negotiatedTLSVersion > 0 && serverHelloResponse.selectedCipherSuite > 0) {
        const sharedKey = diffieHellmanKeyExchange();
        console.log("\nHandshake Successful!");
        console.log(`Shared Secret Key: ${sharedKey}`);
    } else {
        console.log("\nHandshake Failed!");
        if (serverHelloResponse.negotiatedTLSVersion <= 0) {
            console.log("Error: No common TLS version found.");
        }
        if (serverHelloResponse.selectedCipherSuite <= 0) {
            console.log("Error: No common cipher suite found.");
        }
    }

    rl.close();
}

main();