#!/bin/sh

# Script by Persian Prince for https://github.com/OpenVisionE2
# You're not allowed to remove my copyright or reuse this script without putting this header.

setup_git() {
  git config --global user.email "bot@tipomimmo@gmail.com"
  git config --global user.name "osno-bot"
}

commit_files() {
  git clean -fd
  rm -rf *.pyc
  rm -rf *.pyo
  rm -rf *.mo

  # Verifica l'esistenza del branch prima del checkout
  if git show-ref --verify --quiet refs/heads/pyton-3.13; then
    git checkout pyton-3.13
  else
    echo "Branch pyton-3.13 non trovato!"
    exit 1
  fi

  # Esegui gli script solo se esistono
  if [ -f "./CI/chmod.sh" ]; then
    ./CI/chmod.sh
  else
    echo "File ./CI/chmod.sh non trovato!"
    exit 1
  fi

  if [ -f "./CI/dos2unix.sh" ]; then
    ./CI/dos2unix.sh
  else
    echo "File ./CI/dos2unix.sh non trovato!"
    exit 1
  fi

  if [ -f "./CI/PEP8.sh" ]; then
    ./CI/PEP8.sh
  else
    echo "File ./CI/PEP8.sh non trovato!"
    exit 1
  fi
}

upload_files() {
  # Aggiungi remote se non esiste già
  git remote add upstream https://${GITHUB_TOKEN}@github.com/osno/osno.git > /dev/null 2>&1

  # Esegui il pull prima del push per evitare conflitti
  git pull --rebase origin pyton-3.13

  # Push con gestione errore
  git push --quiet upstream pyton-3.13 || { echo "Failed to push!"; exit 1; }
}

setup_git
commit_files
upload_files

