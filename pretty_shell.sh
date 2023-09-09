apt-get -o Acquire::ForceIPv4=true update
apt-get -o Acquire::ForceIPv4=true --with-new-pkgs upgrade -y
apt autoremove -y
apt-get -o Acquire::ForceIPv4=true install -y git zsh curl
sh -c "$(curl -fsSL https://raw.githubusercontent.com/ohmyzsh/ohmyzsh/master/tools/install.sh)"
git clone --depth=1 https://github.com/romkatv/powerlevel10k.git ${ZSH_CUSTOM:-$HOME/.oh-my-zsh/custom}/themes/powerlevel10k
mv ./conf/.* ~/
