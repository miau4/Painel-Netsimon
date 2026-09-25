dnstt-server -- binário embutido no painel
===========================================

Arquivo: /etc/painel/dnstt-server
Origem:  fonte oficial do autor (David Fifield), www.bamsoftware.com/git/dnstt.git
Commit usado: 6adedaa823c6d7a56e795871e9d406e37f192614 (via mirror github.com/Mygod/dnstt,
              que segue o mesmo histórico -- o servidor oficial bamsoftware.com usa
              "dumb http transport", sem suporte a clone raso/CDN, então usei o mirror
              só pra facilitar o download; o código é o mesmo)
Plataforma:   linux/amd64
SHA-256:      f7d35e52830e90cd136a40cab548106dace5354e1d2fa69766ae62aea7778233

Por que não compila mais sozinho na hora (como numa versão anterior do painel):
o admin decidiu não depender de baixar código/toolchain de nenhum repositório
online durante a instalação -- nem do Go, nem do git, nem do próprio dnstt.
Por isso agora o binário já compilado fica junto com o projeto, e o painel só
copia ele pra /etc/slowdns/dnstt-server na hora de configurar.

Como reproduzir esse build do zero (só é preciso se um dia quiser atualizar
pra uma versão mais nova do dnstt):

    apt-get install -y golang-go git
    git clone https://github.com/Mygod/dnstt.git dnstt-src
    cd dnstt-src
    git checkout 6adedaa823c6d7a56e795871e9d406e37f192614

    # go.mod pede go >= 1.21; se a toolchain instalada for mais antiga,
    # os pacotes golang.org/x/* podem não resolver sem acesso a
    # proxy.golang.org -- nesse caso, adicione ao final do go.mod:
    #   replace golang.org/x/crypto => github.com/golang/crypto v0.21.0
    #   replace golang.org/x/net    => github.com/golang/net    v0.23.0
    #   replace golang.org/x/sys    => github.com/golang/sys    v0.18.0
    #   replace golang.org/x/text   => github.com/golang/text   v0.14.0
    #   replace golang.org/x/sync   => github.com/golang/sync   v0.6.0
    # e rode com GOPROXY=direct GOSUMDB=off GOFLAGS=-mod=mod

    go build -o dnstt-server ./dnstt-server
    strip dnstt-server   # opcional, só reduz o tamanho do binário

Depois é só substituir /etc/painel/dnstt-server pelo novo binário.
