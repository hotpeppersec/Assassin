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

## Install Docker

```bash
brew install docker
```

## Run the Tool

```bash
make docker
cd assassin
python assassin.py
```
