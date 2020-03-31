# Quickstart for Mac

## Install brew

[Homebrew Installation](https://docs.brew.sh/Installation)

```bash
mkdir homebrew && curl -L https://github.com/Homebrew/brew/tarball/master|tar xz --strip 1 -C homebrew
brew tap caskroom/cask
```

## Install git

```
brew install git
```

## Install Docker Desktop
[Docker Desktop](https://docs.docker.com/docker-for-mac/install/) Install overview

[Download docker](https://hub.docker.com/editions/community/docker-ce-desktop-mac/) Software package

Complete sofware installer with-in GUI

## Configure apiKeys.py
edit assassin/apiKey.py
configure the various services (VirusTotal, Shodan, etc) with your personal API KEY value

Change default values of apiKeys.py 
Save file with update API key values 
```
vtKey = 'CHANGEME'
shodanKey = 'CHANGEME'
GoogleMapsKey = 'CHANGEME'
dnsdbKey = 'CHANGEME'
GoogleSafeBrowsingKey = 'CHANGEME'
```

## Run the Assassin Tool

```bash
make docker
cd assassin
python assassin.py
```
