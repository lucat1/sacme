package main

import "net/url"

type Account struct {
	Email     string   `toml:"email"`
	AcceptTOS bool     `toml:"accept_tos"`
	Directroy *url.URL `toml:"directory"`
}

type Path struct {
}

type Domain struct {
	Domains []string `toml:"domains"`
	Account Account  `toml:"account"`
	Paths   []Path   `toml:"paths"`
}
