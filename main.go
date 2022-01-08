package main
import (
	"fmt"
	"strconv"
	"math/rand"
	"time"
	"strings"
	"crypto/sha256"
)
var start time.Time
var EBC BlockChain
const (
	NodeNumber     = 100
	MaxChannelSize = 1000
)
func ComputeHashSha256(bytes []byte) string {
    return fmt.Sprintf("%x", sha256.Sum256(bytes))
}
func GenerateRandomNumber() int64{
	var test strings.Builder
	rand.Seed(time.Now().UnixNano())
	for i := 1; i < 7; i++ {
		RandomInteger := rand.Intn(9) + 1
		test.WriteString(strconv.Itoa(RandomInteger))
	}
	s,err := strconv.Atoi(test.String())
	if err == nil {
		return int64(s)
	} else {
        return int64(0)
    }
}


type BlockChain struct {
	chain []Block
}

type Block struct {
    hash int64
	Proof int64
    PreviousHash int64
}

func (bc *BlockChain) NewBlock(proof int64, previousHash int64) Block {
	prevHash := previousHash
    newBlock := Block{
        hash :		  GenerateRandomNumber(),
        Proof:        proof,
        PreviousHash: prevHash,
    }

    bc.chain = append(bc.chain, newBlock)
    return newBlock
}

func (bc *BlockChain) FirstNewBlock(proof int64, previousHash int64) Block {
	prevHash := previousHash
    newBlock := Block{
        hash :		  6666,
        Proof:        proof,
        PreviousHash: prevHash,
    }

    bc.chain = append(bc.chain, newBlock)
    return newBlock
}

func (bc *BlockChain) ProofOfWork(lastProof int64) int64 {
	num := 1000 + (rand.Intn(9) + 1)*50
	// fmt.Println(num)
    time.Sleep(time.Duration(num) * time.Millisecond)
    return GenerateRandomNumber()
}

func (bc *BlockChain) ValidProof(lastProof, proof int64) bool {
    return true
}

func (bc *BlockChain) LastBlock() Block {
    return bc.chain[len(bc.chain)-1]
}


func computeHashForBlock(block Block) int64 {
    return block.hash
}

func (bc *BlockChain) ValidateChain(chain *[]Block) bool {
    lastBlock := (*chain)[0]
    currentIndex := 1
    for currentIndex < len(*chain) {
        block := (*chain)[currentIndex]
        // Check that the hash of the block is correct
        if block.PreviousHash != computeHashForBlock(lastBlock) {
            return false
        }
        // Check that the Proof of Work is correct
        if !bc.ValidProof(lastBlock.Proof, block.Proof) {
            return false
        }
        lastBlock = block
        currentIndex += 1
    }
    return true
}

func NewBlockChain() *BlockChain {
    newBlockChain := &BlockChain{
        chain:        make([]Block, 0),
    }
    // Initial, sentinel block
    newBlockChain.FirstNewBlock(100, 1111)
    return newBlockChain
}

func (bc *BlockChain) ResolveConflicts(bc2 *BlockChain) bool {
    // We're only looking for chains longer than ours
    maxLength := len(bc.chain)
	otherBlockChain := bc2.chain
	newChain := make([]Block, 0)

    // Check if the length is longer and the chain is valid
    if len(otherBlockChain) > maxLength {
        maxLength = len(otherBlockChain)
        newChain = otherBlockChain
    }

    // Replace our chain if we discovered a new, valid chain longer than ours
    if len(newChain) > 0 {
        bc.chain = newChain
        return true
    }
    return false
}
// type BlockChain struct {
// 	chain []Block
// }
// May need other fields
type Node struct {
	id          uint64
	peers       map[uint64]chan Message
	receiveChan chan Message
	chain 		*BlockChain
}

// Define your message's struct here
type Message struct {
	sender uint64
	bc 	   BlockChain
}

func NewNode(id uint64, peers map[uint64]chan Message, recvChan chan Message, bc *BlockChain) *Node {
	return &Node{
		id:          id,
		peers:       peers,
		receiveChan: recvChan,
		chain:		 bc,
	}
}

func (n *Node) Run() {
	fmt.Println("start node : ", n.id)
	go n.Receive()
	go n.Mine()
}

func (n *Node) Mine() {
	for {
		//fmt.Println(n.id, "  Mining some coins")
		bc := n.chain
		// We run the proof of work algorithm to get the next proof...
		proof := bc.ProofOfWork(bc.LastBlock().Proof)

		// Forge the new Block by adding it to the chain
		bc.NewBlock(proof, bc.LastBlock().hash)
		// fmt.Println("test node : ", n.id, "Blockchain: ", bc)
		
		if (bc.ValidateChain(&(bc.chain))) {
			fmt.Println("Node", n.id, "Mined", " New Length is", len(n.chain.chain))
			if (len(n.chain.chain) == 100) {
				elapsed := time.Since(start)
    			fmt.Println("生成100个节点耗时:", elapsed)
			}
			n.Broadcast(Message{sender : n.id, bc : *(n.chain)})
		}
	}
}

func (n *Node) Receive() {
	for {
		select {
		case msg := <-n.receiveChan:
			n.handler(msg)
		}
	}
}


func (n *Node) handler(msg Message) {
	//fmt.Println("Node", n.id, "received message from node", msg.sender)
	received_bc := msg.bc
	// fmt.Println(n.chain,"   ",received_bc)
	if (received_bc.ValidateChain(&received_bc.chain)) {
		if n.chain.ResolveConflicts(&received_bc) {
			//fmt.Println("Node", n.id, "blockchain was replaced by", msg.sender)
		}	else {
			//fmt.Println("Node", n.id, "keep own blockchain")
		}
	}
}

func (n *Node) Broadcast(msg Message) {
	for id, ch := range n.peers {
		if id == n.id {
			continue
		}
		ch <- msg
	}
}



func main() {
	nodes := make([]*Node, NodeNumber)
	peers := make(map[uint64]chan Message)
	for i := 0; i < NodeNumber; i++ {
		peers[uint64(i)] = make(chan Message, MaxChannelSize)
	}
	for i := uint64(0); i < NodeNumber; i++ {
		var bc = NewBlockChain()
		nodes[i] = NewNode(i, peers, peers[i], bc)
	}
	start = time.Now()
	// start all nodes
	for i := 0; i < NodeNumber; i++ {
		go nodes[i].Run()
	}

	// block to wait for all nodes' threads
	<-make(chan int)
}
