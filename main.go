package main

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"github.com/The-Ap0stle/Poof/arp_poison"
	"github.com/The-Ap0stle/Poof/ip_spoof"
)

func displayMenu() {
	fmt.Println("\n[+] Menu:")
	fmt.Println("1] IP Spoofer")
	fmt.Println("2] ARP Poison")
	fmt.Println("3] DNS Spoofer")
	fmt.Println("Choose an option (eg: IP Spoofer or 1):")
}

func main() {
	fmt.Println(` ██▓███   ▒█████   ▒█████    █████▒
				 ▓██░  ██▒▒██▒  ██▒▒██▒  ██▒▓██   ▒ 
				 ▓██░ ██▓▒▒██░  ██▒▒██░  ██▒▒████ ░ 
				 ▒██▄█▓▒ ▒▒██   ██░▒██   ██░░▓█▒  ░ 
				 ▒██▒ ░  ░░ ████▓▒░░ ████▓▒░░▒█░    
				 ▒▓▒░ ░  ░░ ▒░▒░▒░ ░ ▒░▒░▒░  ▒ ░    
				 ░▒ ░       ░ ▒ ▒░   ░ ▒ ▒░  ░      
				 ░░       ░ ░ ░ ▒  ░ ░ ░ ▒   ░ ░    
							░ ░      ░ ░          
												`)
	fmt.Println("[$] Welcome to Poof!")
	displayMenu()
	reader := bufio.NewReader(os.Stdin)

	for {
		fmt.Print("\npoof>> ")
		input, _ := reader.ReadString('\n')
		input = strings.TrimSpace(strings.ToLower(input)) // Normalize input

		switch input {
		case "1", "ip spoofer":
			ip_spoof.Start()
		case "2", "arp_poison":
			arp_poison.Start()
		case "exit", "quit":
			fmt.Println("\n[$] Exiting Poof. Goodbye!")
			return
		case "menu":
			displayMenu()
		default:
			fmt.Println("[!] Invalid option. Type 'menu' to display the menu.")
		}
	}
}
