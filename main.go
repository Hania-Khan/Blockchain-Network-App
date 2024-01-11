//main.go

package main

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/gob"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"log"
	"math/big"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

// Block represents a block in the blockchain.
type Block struct {
	Index        int
	Timestamp    int64
	Transactions []string
	PrevHash     string
	Hash         string
	Nonce        int
	MerkleRoot   string
}

// Blockchain represents the blockchain structure.
type Blockchain struct {
	Chain  []Block
	Length int
	mutex  sync.Mutex
}

// Node represents a node in the blockchain network.
type Node struct {
	Address string
	Stake   int // Amount of stake for PoS
}

// Message represents a message sent between nodes.
type Message struct {
	Command string
	Data    []byte
}

// Network represents the blockchain network.
type Network struct {
	Nodes            []Node
	Blockchain       Blockchain
	mutex            sync.Mutex
	CertificateFile  string // File path for TLS certificate
	PrivateKeyFile   string // File path for TLS private key
	PeerDiscoveryURL string // URL for peer discovery
}

// Updated NewBlockchain method to include a genesis block
func NewBlockchain() *Blockchain {
	// Create a genesis block with arbitrary data
	genesisBlock := Block{
		Index:        0,
		Timestamp:    time.Now().Unix(),
		Transactions: []string{"Genesis Transaction"},
		PrevHash:     "",
		Nonce:        0,
		MerkleRoot:   "",
	}
	genesisBlock.Hash = CalculateHash(genesisBlock)

	return &Blockchain{
		Chain:  []Block{genesisBlock},
		Length: 1,
	}
}

// NewNode method updated to include the stake parameter
func NewNode(address string, stake int) Node {
	return Node{
		Address: address,
		Stake:   stake,
	}
}

// NewNetwork initializes a new blockchain network.
func NewNetwork() *Network {
	return &Network{
		Nodes:      make([]Node, 0),
		Blockchain: *NewBlockchain(),
	}
}

// CalculateHash calculates the hash of a block.
func CalculateHash(block Block) string {
	record := fmt.Sprintf("%d%d%s%s%d%s", block.Index, block.Timestamp, block.Transactions, block.PrevHash, block.Nonce, block.MerkleRoot)
	hash := sha256.New()
	hash.Write([]byte(record))
	return fmt.Sprintf("%x", hash.Sum(nil))
}

// GenerateMerkleRoot generates the Merkle tree root from a list of transactions.
func GenerateMerkleRoot(transactions []string) string {
	if len(transactions) == 0 {
		return ""
	}
	if len(transactions) == 1 {
		return transactions[0]
	}

	var newTransactions []string
	for i := 0; i < len(transactions); i += 2 {
		first := transactions[i]
		second := ""
		if i+1 < len(transactions) {
			second = transactions[i+1]
		}
		combined := first + second
		newHash := sha256.Sum256([]byte(combined))
		newTransactions = append(newTransactions, fmt.Sprintf("%x", newHash))
	}

	return GenerateMerkleRoot(newTransactions)
}

// GenerateBlock creates a new block in the blockchain.
func (bc *Blockchain) GenerateBlock(transactions []string) Block {
	bc.mutex.Lock()
	defer bc.mutex.Unlock()

	var prevHash string
	if bc.Length > 0 {
		prevHash = bc.Chain[bc.Length-1].Hash
	}

	merkleRoot := GenerateMerkleRoot(transactions)
	block := Block{
		Index:        bc.Length + 1,
		Timestamp:    time.Now().Unix(),
		Transactions: transactions,
		PrevHash:     prevHash,
		Nonce:        0,
		MerkleRoot:   merkleRoot,
	}

	for {
		block.Hash = CalculateHash(block)
		if block.IsValid() {
			break
		}
		block.Nonce++
	}

	return block
}

// AddBlock adds a block to the blockchain.
func (bc *Blockchain) AddBlock(block Block) {
	bc.mutex.Lock()
	defer bc.mutex.Unlock()

	bc.Chain = append(bc.Chain, block)
	bc.Length++
}

// IsValid checks if a block is valid.
func (block Block) IsValid() bool {
	return strings.HasPrefix(block.Hash, "00") // Use strings.HasPrefix to check for the prefix
}

// BroadcastBlock broadcasts a block to all nodes in the network.
// Updated BroadcastBlock method to use TLS and encrypt data
func (n *Network) BroadcastBlock(newBlock Block) {
	n.mutex.Lock()
	defer n.mutex.Unlock()

	for _, node := range n.Nodes {
		url := fmt.Sprintf("https://%s/broadcast", node.Address)

		// Encode the block to JSON
		encodedBlock, err := json.Marshal(newBlock)
		if err != nil {
			log.Println("Error encoding block:", err)
			return
		}

		// Send the block using HTTPS POST
		resp, err := http.Post(url, "application/json", bytes.NewBuffer(encodedBlock))
		if err != nil {
			log.Println("Error sending block to node:", node.Address, err)
			continue
		}
		defer resp.Body.Close()

		// Handle the response if needed
	}
}

// Updated HandleIncomingBlocks method to use TLS and decrypt data
func (n *Network) HandleIncomingBlocks() {
	cert, err := tls.LoadX509KeyPair(n.CertificateFile, n.PrivateKeyFile)
	if err != nil {
		log.Fatal("Error loading TLS key pair:", err)
	}

	config := tls.Config{
		Certificates: []tls.Certificate{cert},
	}

	listener, err := tls.Listen("tcp", ":8080", &config) // Change port as needed
	if err != nil {
		log.Fatal("Error starting listener:", err)
	}
	defer listener.Close()

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Println("Error accepting connection:", err)
			continue
		}

		go func(c net.Conn) {
			defer c.Close()

			// Decrypt the incoming data using TLS
			tlsConn, ok := c.(*tls.Conn)
			if !ok {
				log.Println("Error casting to TLS connection")
				return
			}
			if err := tlsConn.Handshake(); err != nil {
				log.Println("Error during TLS handshake:", err)
				return
			}

			var receivedMessage Message
			err := gob.NewDecoder(c).Decode(&receivedMessage)
			if err != nil {
				log.Println("Error decoding message:", err)
				return
			}

			switch receivedMessage.Command {
			case "BLOCK":
				var receivedBlock Block
				err := gob.NewDecoder(bytes.NewReader(receivedMessage.Data)).Decode(&receivedBlock)
				if err != nil {
					log.Println("Error decoding block:", err)
					return
				}

				if receivedBlock.IsValid() && n.VerifyMerkleRoot(receivedBlock.Transactions, receivedBlock.MerkleRoot) {
					n.mutex.Lock()
					n.Blockchain.AddBlock(receivedBlock)
					n.mutex.Unlock()

					log.Println("Received and added a valid block from", c.RemoteAddr())
				} else {
					log.Println("Received an invalid block from", c.RemoteAddr())
				}
			}
		}(conn)
	}
}

// DiscoverPeers method to dynamically discover and connect to other nodes
func (n *Network) DiscoverPeers() {
	for {
		// Make a request to the peer discovery server to get a list of available nodes
		resp, err := http.Get(n.PeerDiscoveryURL)
		if err != nil {
			log.Println("Error getting peers from discovery server:", err)
			time.Sleep(5 * time.Second) // Retry after a delay
			continue
		}
		defer resp.Body.Close()

		// Decode the response to get the list of nodes
		var discoveredNodes []Node
		err = json.NewDecoder(resp.Body).Decode(&discoveredNodes)
		if err != nil {
			log.Println("Error decoding peers from discovery server:", err)
			time.Sleep(5 * time.Second) // Retry after a delay
			continue
		}

		// Add discovered nodes to the network
		n.mutex.Lock()
		n.Nodes = append(n.Nodes, discoveredNodes...)
		n.mutex.Unlock()

		// Sleep for a duration before the next discovery attempt
		time.Sleep(30 * time.Second)
	}
}

// VerifyMerkleRoot verifies the Merkle root of transactions in a block.
func (n *Network) VerifyMerkleRoot(transactions []string, merkleRoot string) bool {
	calculatedMerkleRoot := GenerateMerkleRoot(transactions)
	return calculatedMerkleRoot == merkleRoot
}

// PrintBlockchain prints the information of all blocks in the blockchain.
func (bc *Blockchain) PrintBlockchain() {
	bc.mutex.Lock()
	defer bc.mutex.Unlock()

	for _, block := range bc.Chain {
		fmt.Printf("\nBlock %d:\n", block.Index)
		fmt.Printf("Transactions: %v\n", block.Transactions)
		fmt.Printf("Timestamp: %d\n", block.Timestamp)
		fmt.Printf("Previous Hash: %s\n", block.PrevHash)
		fmt.Printf("Hash: %s\n", block.Hash)
		fmt.Printf("Nonce: %d\n", block.Nonce)
		fmt.Printf("Merkle Root: %s\n", block.MerkleRoot)
	}
}

// Function to create a self-signed TLS certificate and private key
func generateSelfSignedCertificate(certFile, keyFile string) error {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return err
	}

	notBefore := time.Now()
	notAfter := notBefore.Add(365 * 24 * time.Hour) // Valid for 1 year

	template := x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{Organization: []string{"FAST"}},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return err
	}

	certFileData := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyFileData := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)})

	if err := ioutil.WriteFile(certFile, certFileData, 0644); err != nil {
		return err
	}

	if err := ioutil.WriteFile(keyFile, keyFileData, 0644); err != nil {
		return err
	}

	return nil
}

func main() {
	network := NewNetwork()

	// Load TLS certificate and private key
	network.CertificateFile = "path/to/cert.pem"
	network.PrivateKeyFile = "path/to/key.pem"

	// Add nodes to the network
	node1 := NewNode("localhost:8081", 10) // Node with stake 10 for PoS
	node2 := NewNode("localhost:8082", 5)  // Node with stake 5 for PoS
	network.Nodes = append(network.Nodes, node1, node2)

	// Set the file paths for the TLS certificate and private key
	certFile := "path/to/cert.pem"
	keyFile := "path/to/key.pem"

	// Check if the certificate and private key files exist, generate them if not
	if _, err := os.Stat(certFile); os.IsNotExist(err) {
		log.Println("Generating self-signed TLS certificate and private key...")
		err := generateSelfSignedCertificate(certFile, keyFile)
		if err != nil {
			log.Fatal("Error generating TLS certificate and private key:", err)
		}
	}

	// Set the URL for peer discovery
	network.PeerDiscoveryURL = "https://peer-discovery-server/discover"

	// Start handling incoming blocks in a separate goroutine
	go network.HandleIncomingBlocks()

	// Start the peer discovery process in a separate goroutine
	go network.DiscoverPeers()

	// Main loop for user interaction
	for {
		fmt.Println("\nMenu:")
		fmt.Println("1. Create Block")
		fmt.Println("2. Display Blockchain")
		fmt.Println("3. Exit")
		fmt.Print("Select option: ")

		var choice int
		fmt.Scan(&choice)

		switch choice {
		case 1:
			var transactions string
			fmt.Print("Enter transactions (comma-separated): ")
			fmt.Scan(&transactions)
			transactionList := strings.Split(transactions, ",") // Split the input into a slice
			newBlock := network.Blockchain.GenerateBlock(transactionList)

			// Broadcast the newly mined block to other nodes
			network.BroadcastBlock(newBlock)

		case 2:
			network.Blockchain.PrintBlockchain()

		case 3:
			fmt.Println("Exiting...")
			return

		default:
			fmt.Println("Invalid choice. Please enter a valid option.")
		}
	}
}
