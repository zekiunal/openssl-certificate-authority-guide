--------------------------
**Disclaimer:** non-English version of the guide contain unofficial translations contributed by our users. They are not binding in any way, are not guaranteed to be accurate, and have no legal effect. The official text is the [English](https://jamielinux.com/docs/openssl-certificate-authority/) version of the website.

--------------------------

# OpenSSL Sertifika Yetkilisi

Bu kılavuz, OpenSSL komut satırı araçlarını kullanarak kendi sertifika yetkilinizi (CA) nasıl kurup kullanacağınızı gösterir. Kendi adınıza hizmet veren Sertifika yetkilisi, intranet web sitesini güvence altına almak için sunucu sertifikaları verebilir veya bir sunucuya kimlik doğrulaması yapmalarını sağlamak için müşterilere sertifikalar üretebilir. Sertifika yetkilisi buna benzer birçok durumda kullanışlı bir çözümdür.

<details>
# OpenSSL Certificate Authority

This guide demonstrates how to act as your own certificate authority (CA) using the OpenSSL command-line tools. This is useful in a number of situations, such as issuing server certificates to secure an intranet website, or for issuing certificates to clients to allow them to authenticate to a server.

[source](https://jamielinux.com/docs/openssl-certificate-authority/)
[discourse](https://discourse.jamielinux.com/)

</details>

## Giriş

OpenSSL, dijital sertifikaları işleme için çeşitli komut satırı araçları sağlayan ücretsiz ve açık kaynak kodlu bir kütüphanedir. Bu araçlardan bazıları bir sertifika yetkilisi olarak kullanılabilir.

Bir sertifika yetkilisi (CA), dijital sertifikaları imzalayan bir oteritedir. Çoğu web sitesi, müşterilerine bağlantılarının güvenli olduğunu bildirme ihtiyacı duyar, bu nedenle alan adları için bir sertifika imzalamak istediklerinde uluslararası geçerliliğe sahip (örneğin, VeriSign, DigiCert) bir sertifika yetkilisine (CA'ya)  ödeme yaparlar.

Bazı durumlarda DigiCert gibi bir sertifika yetkilisine (CA'ya) ödeme yapmak yerine kendi sunucularımızdan birini sertifika yetkilisi (CA'ya) gibi göstermek daha mantıklı olabilir. Bu durumlar genellikle, bir intranet web sitesinin güvenliğini sağlamak veya bir sunucuya kimlik doğrulamasını yapmayı sağlamak için müşterilere sertifikalar (örn., Apache, OpenVPN) üretmek olabilir.

<details>
## Introduction

OpenSSL is a free and open-source cryptographic library that provides several command-line tools for handling digital certificates. Some of these tools can be used to act as a certificate authority.

A certificate authority (CA) is an entity that signs digital certificates. Many websites need to let their customers know that the connection is secure, so they pay an internationally trusted CA (eg, VeriSign, DigiCert) to sign a certificate for their domain.

In some cases it may make more sense to act as your own CA, rather than paying a CA like DigiCert. Common cases include securing an intranet website, or for issuing certificates to clients to allow them to authenticate to a server (eg, Apache, OpenVPN).
</details>

## Anahtar Çiftinin Oluşturulması

Bir sertifika yetkilisi (CA) olarak hareket etmek demek, Özel anahtar  ve genel sertifika çiftlerinin şifrelenmesiyle uğraşmak anlamına gelir. Oluşturacağımız ilk şifreleme çifti, kök çiftidir. Bu, kök anahtardan (root key) (ca.key.pem) ve kök sertifikadan (root certificate) (ca.cert.pem) oluşur. Bu çift, CA'nızın kimliğini oluşturur.

Genellikle kök CA, sunucu veya istemci sertifikalarını doğrudan imzalamaz. Kök CA yalnızca kök CA tarafından kendi adına sertifikalar imzalamaya güvendiği bir veya daha fazla Ara (intermediate) CA oluşturmada kullanılır. Bu en iyi ve en yaygın uygulamadır. Kök anahtara herhangi bir zararlı erişim felakete yol açacağından, kök anahtarının çevrimdışı tutulmasına ve kullanılmamasına izin verir.

> Not : Kök çiftini güvenli bir ortamda oluşturmak en iyi yöntemdir. İdeal olarak, bu ortam, Internet'ten kalıcı olarak izole edilmiş tamamen şifreli, `air gap` bir bilgisayarda olmalıdır. Kablosuz kartı çıkarın ve ethernet bağlantı noktasını tutkalla doldurun.

<details>
## Create the root pair

Acting as a certificate authority (CA) means dealing with cryptographic pairs of private keys and public certificates. The very first cryptographic pair we’ll create is the root pair. This consists of the root key (ca.key.pem) and root certificate (ca.cert.pem). This pair forms the identity of your CA.

Typically, the root CA does not sign server or client certificates directly. The root CA is only ever used to create one or more intermediate CAs, which are trusted by the root CA to sign certificates on their behalf. This is best practice. It allows the root key to be kept offline and unused as much as possible, as any compromise of the root key is disastrous.

> Note: It’s best practice to create the root pair in a secure environment. Ideally, this should be on a fully encrypted, air gapped computer that is permanently isolated from the Internet. Remove the wireless card and fill the ethernet port with glue.
</details>

### Dizinlerin Hazırlanması 

Tüm anahtarları ve sertifikaları saklamak için bir dizin seçin (`/root/ca`).



```
mkdir /root/ca
```

Dizin yapısı oluşturun. `index.txt` ve` serial` dosyaları, imzalı sertifikaları takip etmek için düz bir dosyadır ve veritabanı görevi görürler.


```
cd /root/ca
mkdir certs crl newcerts private
chmod 700 private
touch index.txt
echo 1000 > serial
```

<details>

### Prepare the directory

Choose a directory (`/root/ca`) to store all keys and certificates.

```
mkdir /root/ca
```

Create the directory structure. The `index.txt` and `serial` files act as a flat file database to keep track of signed certificates.

```
cd /root/ca
mkdir certs crl newcerts private
chmod 700 private
touch index.txt
echo 1000 > serial
```

</details>

### Yapılandırma Dosyasını Hazırlayın

OpenSSL'in kullanması için bir yapılandırma dosyası oluşturmanız gerekir. Kök CA yapılandırma dosyasını [Ekler](#) 'dan `/root/ca/openssl.cnf` dosyasına kopyalayın.

`[ca]` bölümü zorunludur. Burada OpenSSL'e `[CA_default]` bölümündeki seçenekleri kullanmasını söylüyoruz.

```
[ ca ]
# `man ca`
default_ca = CA_default
```

`[CA_default]` bölümü bir dizi öntanımlı değer içerir. Daha önce belirlediğiniz dizini işaret ettiğinden emin olun (`/root/ca`).

```
[ CA_default ]
# Directory and file locations.
dir               = /root/ca
certs             = $dir/certs
crl_dir           = $dir/crl
new_certs_dir     = $dir/newcerts
database          = $dir/index.txt
serial            = $dir/serial
RANDFILE          = $dir/private/.rand

# The root key and root certificate.
private_key       = $dir/private/ca.key.pem
certificate       = $dir/certs/ca.cert.pem

# For certificate revocation lists.
crlnumber         = $dir/crlnumber
crl               = $dir/crl/ca.crl.pem
crl_extensions    = crl_ext
default_crl_days  = 30

# SHA-1 is deprecated, so use SHA-2 instead.
default_md        = sha256

name_opt          = ca_default
cert_opt          = ca_default
default_days      = 375
preserve          = no
policy            = policy_strict
```

Kök CA yalnızca ara CA'lar (intermediate CA) oluşturmak için kullanıldığından, tüm kök CA imzaları için `policy_strict` uygularız.

```
[ policy_strict ]
# The root CA should only sign intermediate certificates that match.
# See the POLICY FORMAT section of `man ca`.
countryName             = match
stateOrProvinceName     = match
organizationName        = match
organizationalUnitName  = optional
commonName              = supplied
emailAddress            = optional
```

Ara CA, üçüncü taraflardan gelebilecek sunucu ve istemci sertifikaları imzalarken, tüm ara CA imzaları için policy_loose kuralları uygulanacaktır.

```
[ policy_loose ]
# Allow the intermediate CA to sign a more diverse range of certificates.
# See the POLICY FORMAT section of the `ca` man page.
countryName             = optional
stateOrProvinceName     = optional
localityName            = optional
organizationName        = optional
organizationalUnitName  = optional
commonName              = supplied
emailAddress            = optional
```

`[req]` bölümündeki seçenekler, sertifika veya sertifika imzalama isteği oluştururken uygulanır.

```
[ req ]
# Options for the `req` tool (`man req`).
default_bits        = 2048
distinguished_name  = req_distinguished_name
string_mask         = utf8only

# SHA-1 is deprecated, so use SHA-2 instead.
default_md          = sha256

# Extension to add when the -x509 option is used.
x509_extensions     = v3_ca
```

`[req_distinguished_name]` bölümü, bir sertifika imzalama talebinde gerekli olan bilgileri içerir. İsterseniz bazı varsayılanlar belirleyebilirsiniz.


```
[ req_distinguished_name ]
# See <https://en.wikipedia.org/wiki/Certificate_signing_request>.
countryName                     = Country Name (2 letter code)
stateOrProvinceName             = State or Province Name
localityName                    = Locality Name
0.organizationName              = Organization Name
organizationalUnitName          = Organizational Unit Name
commonName                      = Common Name
emailAddress                    = Email Address

# Optionally, specify some defaults.
countryName_default             = GB
stateOrProvinceName_default     = England
localityName_default            =
0.organizationName_default      = Alice Ltd
#organizationalUnitName_default =
#emailAddress_default           =
```

Sonraki birkaç bölüm, sertifikaları imzalarken uygulanabilecek uzantılardır. Örneğin `-extensions v3_ca` komut satırı argümanını kullarak `[v3_ca]` da belirtilen seçenekleri uygulamış oluruz.

Kök sertifikayı oluştururken `v3_ca` uzantısı için başvuracağız.

```
[ v3_ca ]
# Extensions for a typical CA (`man x509v3_config`).
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always,issuer
basicConstraints = critical, CA:true
keyUsage = critical, digitalSignature, cRLSign, keyCertSign
```

Ara sertifika oluşturduğumuzda `v3_ca_intermediate` uzantısından faydalanacağız. `pathlen:0`, ara CA'nın altında daha fazla sertifika yetkilisinin bulunmamasını sağlar.

```
[ v3_intermediate_ca ]
# Extensions for a typical intermediate CA (`man x509v3_config`).
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always,issuer
basicConstraints = critical, CA:true, pathlen:0
keyUsage = critical, digitalSignature, cRLSign, keyCertSign
```

Uzak kullanıcı kimlik doğrulaması için kullanılan istemci sertifikalarını imzalarken, `usr_cert` uzantısına başvuruda bulunacağız.

```
[ usr_cert ]
# Extensions for client certificates (`man x509v3_config`).
basicConstraints = CA:FALSE
nsCertType = client, email
nsComment = "OpenSSL Generated Client Certificate"
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid,issuer
keyUsage = critical, nonRepudiation, digitalSignature, keyEncipherment
extendedKeyUsage = clientAuth, emailProtection
```

Web sunucuları için kullanılan sunucu sertifikalarını imzalarken `server_cert` uzantısını uygulayacağız.

```
[ server_cert ]
# Extensions for server certificates (`man x509v3_config`).
basicConstraints = CA:FALSE
nsCertType = server
nsComment = "OpenSSL Generated Server Certificate"
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid,issuer:always
keyUsage = critical, digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth
```

Sertifika iptal listelerini oluştururken `crl_ext` uzantısı otomatik olarak uygulanacaktır.

```
[ crl_ext ]
# Extension for CRLs (`man x509v3_config`).
authorityKeyIdentifier=keyid:always
```

Online Sertifika Durumu Protokolü (OCSP) sertifikasını imzalarken 'ocsp' uzantısını uygulayacağız.

```
[ ocsp ]
# Extension for OCSP signing certificates (`man ocsp`).
basicConstraints = CA:FALSE
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid,issuer
keyUsage = critical, digitalSignature
extendedKeyUsage = critical, OCSPSigning
```
<details>

### Prepare the configuration file

You must create a configuration file for OpenSSL to use. Copy the root CA configuration file from the [Appendix](#) to `/root/ca/openssl.cnf`.

The `[ ca ]` section is mandatory. Here we tell OpenSSL to use the options from the `[ CA_default ]` section.

```
[ ca ]
# `man ca`
default_ca = CA_default
```

The `[ CA_default ]` section contains a range of defaults. Make sure you declare the directory you chose earlier (`/root/ca`).

```
[ CA_default ]
# Directory and file locations.
dir               = /root/ca
certs             = $dir/certs
crl_dir           = $dir/crl
new_certs_dir     = $dir/newcerts
database          = $dir/index.txt
serial            = $dir/serial
RANDFILE          = $dir/private/.rand

# The root key and root certificate.
private_key       = $dir/private/ca.key.pem
certificate       = $dir/certs/ca.cert.pem

# For certificate revocation lists.
crlnumber         = $dir/crlnumber
crl               = $dir/crl/ca.crl.pem
crl_extensions    = crl_ext
default_crl_days  = 30

# SHA-1 is deprecated, so use SHA-2 instead.
default_md        = sha256

name_opt          = ca_default
cert_opt          = ca_default
default_days      = 375
preserve          = no
policy            = policy_strict
```

We’ll apply `policy_strict` for all root CA signatures, as the root CA is only being used to create intermediate CAs.

```
[ policy_strict ]
# The root CA should only sign intermediate certificates that match.
# See the POLICY FORMAT section of `man ca`.
countryName             = match
stateOrProvinceName     = match
organizationName        = match
organizationalUnitName  = optional
commonName              = supplied
emailAddress            = optional
```

We’ll apply `policy_loose` for all intermediate CA signatures, as the intermediate CA is signing server and client certificates that may come from a variety of third-parties.

```
[ policy_loose ]
# Allow the intermediate CA to sign a more diverse range of certificates.
# See the POLICY FORMAT section of the `ca` man page.
countryName             = optional
stateOrProvinceName     = optional
localityName            = optional
organizationName        = optional
organizationalUnitName  = optional
commonName              = supplied
emailAddress            = optional
```

Options from the `[ req ]` section are applied when creating certificates or certificate signing requests.

```
[ req ]
# Options for the `req` tool (`man req`).
default_bits        = 2048
distinguished_name  = req_distinguished_name
string_mask         = utf8only

# SHA-1 is deprecated, so use SHA-2 instead.
default_md          = sha256

# Extension to add when the -x509 option is used.
x509_extensions     = v3_ca
```

The `[ req_distinguished_name ]` section declares the information normally required in a certificate signing request. You can optionally specify some defaults.

```
[ req_distinguished_name ]
# See <https://en.wikipedia.org/wiki/Certificate_signing_request>.
countryName                     = Country Name (2 letter code)
stateOrProvinceName             = State or Province Name
localityName                    = Locality Name
0.organizationName              = Organization Name
organizationalUnitName          = Organizational Unit Name
commonName                      = Common Name
emailAddress                    = Email Address

# Optionally, specify some defaults.
countryName_default             = GB
stateOrProvinceName_default     = England
localityName_default            =
0.organizationName_default      = Alice Ltd
#organizationalUnitName_default =
#emailAddress_default           =
```

The next few sections are extensions that can be applied when signing certificates. For example, passing the `-extensions v3_ca` command-line argument will apply the options set in `[ v3_ca ]`.

We’ll apply the `v3_ca` extension when we create the root certificate.

```
[ v3_ca ]
# Extensions for a typical CA (`man x509v3_config`).
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always,issuer
basicConstraints = critical, CA:true
keyUsage = critical, digitalSignature, cRLSign, keyCertSign
```

We’ll apply the `v3_ca_intermediate` extension when we create the intermediate certificate. `pathlen:0` ensures that there can be no further certificate authorities below the intermediate CA.

```
[ v3_intermediate_ca ]
# Extensions for a typical intermediate CA (`man x509v3_config`).
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always,issuer
basicConstraints = critical, CA:true, pathlen:0
keyUsage = critical, digitalSignature, cRLSign, keyCertSign
```

We’ll apply the `usr_cert` extension when signing client certificates, such as those used for remote user authentication.

```
[ usr_cert ]
# Extensions for client certificates (`man x509v3_config`).
basicConstraints = CA:FALSE
nsCertType = client, email
nsComment = "OpenSSL Generated Client Certificate"
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid,issuer
keyUsage = critical, nonRepudiation, digitalSignature, keyEncipherment
extendedKeyUsage = clientAuth, emailProtection
```

We’ll apply the `server_cert` extension when signing server certificates, such as those used for web servers.

```
[ server_cert ]
# Extensions for server certificates (`man x509v3_config`).
basicConstraints = CA:FALSE
nsCertType = server
nsComment = "OpenSSL Generated Server Certificate"
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid,issuer:always
keyUsage = critical, digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth
```

The `crl_ext` extension is automatically applied when creating certificate revocation lists.

```
[ crl_ext ]
# Extension for CRLs (`man x509v3_config`).
authorityKeyIdentifier=keyid:always
```

We’ll apply the `ocsp` extension when signing the Online Certificate Status Protocol (OCSP) certificate.

```
[ ocsp ]
# Extension for OCSP signing certificates (`man ocsp`).
basicConstraints = CA:FALSE
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid,issuer
keyUsage = critical, digitalSignature
extendedKeyUsage = critical, OCSPSigning
```
</details>

### Kök Anahtarın Oluşturulması

Kök anahtarı oluşturun (`ca.key.pem`) ve kesinlikle güvende olmasını sağlayın. Kök anahtarına sahip herkes güvenilir sertifikalar verebilir. Kök anahtarını AES 256-bit ile güçlü bir parola kullanarak şifreleyin.

> Not: Tüm kök ve ara sertifika yetkilileri için 4096 bit şifreleme kullanın. 4096 bit şifreleme ile de kısa bir sürede sunucu ve istemci sertifikalarını imzalayabilirsiniz.

```
cd /root/ca
openssl genrsa -aes256 -out private/ca.key.pem 4096

Enter pass phrase for ca.key.pem: secretpassword
Verifying - Enter pass phrase for ca.key.pem: secretpassword

chmod 400 private/ca.key.pem
```

<details>
### Create the root key

Create the root key (`ca.key.pem`) and keep it absolutely secure. Anyone in possession of the root key can issue trusted certificates. Encrypt the root key with AES 256-bit encryption and a strong password.

> Note : Use 4096 bits for all root and intermediate certificate authority keys. You’ll still be able to sign server and client certificates of a shorter length.

```
cd /root/ca
openssl genrsa -aes256 -out private/ca.key.pem 4096

Enter pass phrase for ca.key.pem: secretpassword
Verifying - Enter pass phrase for ca.key.pem: secretpassword

chmod 400 private/ca.key.pem
```
</details>

### Kök Sertifikayı Oluşturun

Bir kök sertifika (`ca.cert.pem`) oluşturmak için kök anahtarını (`ca.key.pem`) kullanın. Kök sertifikaya yirmi yıl gibi uzun bir son kullanma tarihi verin. Kök sertifikanın süresi dolduğunda, CA tarafından imzalanmış tüm sertifikalar geçersiz olur.

> Not: `req` aracını her kullandığınızda,` -config` seçeneği ile kullanılacak bir konfigürasyon dosyası belirtmelisiniz, aksi halde OpenSSL varsayılan olarak tanımlı `/etc/pki/tls/openssl.cnf` dosyasını kullanacaktır.

```
cd /root/ca
openssl req -config openssl.cnf -key private/ca.key.pem -new -x509 -days 7300 -sha256 -extensions v3_ca -out certs/ca.cert.pem

Enter pass phrase for ca.key.pem: secretpassword
You are about to be asked to enter information that will be incorporated
into your certificate request.
-----
Country Name (2 letter code) [XX]:GB
State or Province Name []:England
Locality Name []:
Organization Name []:Alice Ltd
Organizational Unit Name []:Alice Ltd Certificate Authority
Common Name []:Alice Ltd Root CA
Email Address []:

chmod 444 certs/ca.cert.pem
```

<details>
### Create the root certificate

Use the root key (`ca.key.pem`) to create a root certificate (`ca.cert.pem`). Give the root certificate a long expiry date, such as twenty years. Once the root certificate expires, all certificates signed by the CA become invalid.

> Note: Whenever you use the `req` tool, you must specify a configuration file to use with the `-config` option, otherwise OpenSSL will default to `/etc/pki/tls/openssl.cnf`.

```
cd /root/ca
openssl req -config openssl.cnf -key private/ca.key.pem -new -x509 -days 7300 -sha256 -extensions v3_ca -out certs/ca.cert.pem

Enter pass phrase for ca.key.pem: secretpassword
You are about to be asked to enter information that will be incorporated
into your certificate request.
-----
Country Name (2 letter code) [XX]:GB
State or Province Name []:England
Locality Name []:
Organization Name []:Alice Ltd
Organizational Unit Name []:Alice Ltd Certificate Authority
Common Name []:Alice Ltd Root CA
Email Address []:

chmod 444 certs/ca.cert.pem
```
</details>

### Kök Sertifikayı Doğrulayın

```
openssl x509 -noout -text -in certs/ca.cert.pem
```

Çıktı şu şekilde olacaktır:

* Kullanılan İmza Algoritması (`Signature Algorithm`)
* Sertifika geçerlilik tarihleri (`Validity`)
* Genel Anahtar bit uzunluğu (`Public-Key`)
* Sertifikayı imzalayan Sağlayıcı (`Issuer`)
* Sertifika kendisine atıfta bulunan Konu (`Subject`)

Sertifika kendinden imzalı olduğu için "Sağlayıcı" ve "Konu" aynıdır. Tüm kök sertifikaların kendinden imzalı olduğunu unutmayın.

```
Signature Algorithm: sha256WithRSAEncryption
    Issuer: C=GB, ST=England,
            O=Alice Ltd, OU=Alice Ltd Certificate Authority,
            CN=Alice Ltd Root CA
    Validity
        Not Before: Apr 11 12:22:58 2015 GMT
        Not After : Apr  6 12:22:58 2035 GMT
    Subject: C=GB, ST=England,
             O=Alice Ltd, OU=Alice Ltd Certificate Authority,
             CN=Alice Ltd Root CA
    Subject Public Key Info:
        Public Key Algorithm: rsaEncryption
            Public-Key: (4096 bit)
```

Çıktı ayrıca X509v3 uzantılarını gösterir. `v3_ca` uzantısını uyguladık, bu nedenle `[v3_ca]`'dan gelen seçenekler çıktıyı etkileyecektir.

```
X509v3 extensions:
    X509v3 Subject Key Identifier:
        38:58:29:2F:6B:57:79:4F:39:FD:32:35:60:74:92:60:6E:E8:2A:31
    X509v3 Authority Key Identifier:
        keyid:38:58:29:2F:6B:57:79:4F:39:FD:32:35:60:74:92:60:6E:E8:2A:31

    X509v3 Basic Constraints: critical
        CA:TRUE
    X509v3 Key Usage: critical
        Digital Signature, Certificate Sign, CRL Sign
```

<details>
### Verify the root certificate

```
openssl x509 -noout -text -in certs/ca.cert.pem
```

The output shows:

* the Signature Algorithm used
* the dates of certificate Validity
* the Public-Key bit length
* the Issuer, which is the entity that signed the certificate
* the Subject, which refers to the certificate itself

The `Issuer` and `Subject` are identical as the certificate is self-signed. Note that all root certificates are self-signed.

```
Signature Algorithm: sha256WithRSAEncryption
    Issuer: C=GB, ST=England,
            O=Alice Ltd, OU=Alice Ltd Certificate Authority,
            CN=Alice Ltd Root CA
    Validity
        Not Before: Apr 11 12:22:58 2015 GMT
        Not After : Apr  6 12:22:58 2035 GMT
    Subject: C=GB, ST=England,
             O=Alice Ltd, OU=Alice Ltd Certificate Authority,
             CN=Alice Ltd Root CA
    Subject Public Key Info:
        Public Key Algorithm: rsaEncryption
            Public-Key: (4096 bit)
```

The output also shows the X509v3 extensions. We applied the `v3_ca` extension, so the options from `[ v3_ca ]` should be reflected in the output.

```
X509v3 extensions:
    X509v3 Subject Key Identifier:
        38:58:29:2F:6B:57:79:4F:39:FD:32:35:60:74:92:60:6E:E8:2A:31
    X509v3 Authority Key Identifier:
        keyid:38:58:29:2F:6B:57:79:4F:39:FD:32:35:60:74:92:60:6E:E8:2A:31

    X509v3 Basic Constraints: critical
        CA:TRUE
    X509v3 Key Usage: critical
        Digital Signature, Certificate Sign, CRL Sign
```
</details>

## Ara (intermediate) Anahtar Çifti Oluşturun

Bir ara sertifika yetkilisi (CA), kök CA adına sertifikalar imzalayabilen bir alt mercidir. Kök CA, ara sertifikayı imzalar ve bir güven zinciri oluşturur.

Bir ara CA kullanmanın amacı öncelikle güvenliği sağlamaktır. Kök anahtarı çevrimdışı tutulur ve olabildiğince az kullanılır. Eğer Ara anahtar ele geçirilirse, kök CA, ara sertifikayı iptal edebilir ve yeni bir ara şifreleme çifti oluşturabilir.

<details>

## Create the intermediate pair

An intermediate certificate authority (CA) is an entity that can sign certificates on behalf of the root CA. The root CA signs the intermediate certificate, forming a chain of trust.

The purpose of using an intermediate CA is primarily for security. The root key can be kept offline and used as infrequently as possible. If the intermediate key is compromised, the root CA can revoke the intermediate certificate and create a new intermediate cryptographic pair.

</details>

### Dizini Hazırlayın

Kök CA dosyaları `/root/ca` klasörinde saklanır. Ara CA dosyalarını saklamak için farklı bir dizin seçin (`/root/ca/intermediate`).

```
mkdir /root/ca/intermediate
```

Kök CA dosyaları için kullanılan aynı dizin yapısını oluşturun. Sertifika imzalama taleplerini tutmak için bir `csr` dizini yaratmak da uygundur.

```
cd /root/ca/intermediate
mkdir certs crl csr newcerts private
chmod 700 private
touch index.txt
echo 1000 > serial
```

Ara CA dizin ağacına bir `crlnumber` dosyası ekleyin. `crlnumber`, sertifika iptal listelerini takip etmek için kullanılır.

```
echo 1000 > /root/ca/intermediate/crlnumber
```

Ara CA yapılandırma dosyasını [Ek](#)'ten `/root/ca/intermediate/openssl.cnf` dosyasına kopyalayın. 

Kök CA yapılandırma dosyasıyla karşılaştırıldığında beş seçeneğin farklı olduğunu görürüz:

```
[ CA_default ]
dir             = /root/ca/intermediate
private_key     = $dir/private/intermediate.key.pem
certificate     = $dir/certs/intermediate.cert.pem
crl             = $dir/crl/intermediate.crl.pem
policy          = policy_loose
```

<details>
### Prepare the directory

The root CA files are kept in `/root/ca`. Choose a different directory (`/root/ca/intermediate`) to store the intermediate CA files.

```
mkdir /root/ca/intermediate
```

Create the same directory structure used for the root CA files. It’s convenient to also create a `csr` directory to hold certificate signing requests.

```
cd /root/ca/intermediate
mkdir certs crl csr newcerts private
chmod 700 private
touch index.txt
echo 1000 > serial
```

Add a `crlnumber` file to the intermediate CA directory tree. `crlnumber` is used to keep track of certificate revocation lists.

```
echo 1000 > /root/ca/intermediate/crlnumber
```

Copy the intermediate CA configuration file from the Appendix to `/root/ca/intermediate/openssl.cnf`. Five options have been changed compared to the root CA configuration file:

```
[ CA_default ]
dir             = /root/ca/intermediate
private_key     = $dir/private/intermediate.key.pem
certificate     = $dir/certs/intermediate.cert.pem
crl             = $dir/crl/intermediate.crl.pem
policy          = policy_loose
```
</details>

### Ara Anahtarı Oluşturun

Ara anahtarı oluşturun (`intermediate.key.pem`). Ara anahtarı AES 256-bit ile güçlü bir parola kullanarak şifreleyin.

```
cd /root/ca
openssl genrsa -aes256 -out intermediate/private/intermediate.key.pem 4096

Enter pass phrase for intermediate.key.pem: secretpassword
Verifying - Enter pass phrase for intermediate.key.pem: secretpassword

chmod 400 intermediate/private/intermediate.key.pem
```

<details>

### Create the intermediate key

Create the intermediate key (`intermediate.key.pem`). Encrypt the intermediate key with AES 256-bit encryption and a strong password.

```
cd /root/ca
openssl genrsa -aes256 -out intermediate/private/intermediate.key.pem 4096

Enter pass phrase for intermediate.key.pem: secretpassword
Verifying - Enter pass phrase for intermediate.key.pem: secretpassword

chmod 400 intermediate/private/intermediate.key.pem
```
</details>

### Ara Sertifika Oluşturun

Bir sertifika imzalama isteği (CSR) oluşturmak için ara anahtarı kullanın. Yapılandırma ayarları genellikle kök CA ile eşleşmelidir. Ancak Ortak Ad (**Common Name**) farklı olmalıdır.

> Uyarı: Ara CA yapılandırma dosyasını belirttiğinizden emin olun (`intermediate/openssl.cnf`).

```
cd /root/ca
# openssl req -config intermediate/openssl.cnf -new -sha256 -key intermediate/private/intermediate.key.pem \
      -out intermediate/csr/intermediate.csr.pem

Enter pass phrase for intermediate.key.pem: secretpassword
You are about to be asked to enter information that will be incorporated
into your certificate request.
-----
Country Name (2 letter code) [XX]:GB
State or Province Name []:England
Locality Name []:
Organization Name []:Alice Ltd
Organizational Unit Name []:Alice Ltd Certificate Authority
Common Name []:Alice Ltd Intermediate CA
Email Address []:
```

Bir ara sertifika oluşturmak için, Kök CA ile `v3_intermediate_ca` uzantısını kullarak ara CSR'yi imzalayın. Ara sertifika kök sertifikadan daha kısa bir süre geçerli olmalıdır. On yıl uygun olabilir.

> Uyarı: Bu sefer, kök CA yapılandırma dosyasını belirtin (`/root/ca/openssl.cnf`).

```
cd /root/ca
openssl ca -config openssl.cnf -extensions v3_intermediate_ca -days 3650 -notext -md sha256 \
      -in intermediate/csr/intermediate.csr.pem -out intermediate/certs/intermediate.cert.pem

Enter pass phrase for ca.key.pem: secretpassword
Sign the certificate? [y/n]: y

chmod 444 intermediate/certs/intermediate.cert.pem
```

`index.txt` dosyası, OpenSSL `ca` aracının sertifika veritabanının depoladığı yerdir. Bu dosyayı silmeyin veya düzenlemeyin. Şimdi; `index.txt` dosyası, ara sertifika ile ilgili bir satır içermelidir.

```
V 250408122707Z 1000 unknown ... /CN=Alice Ltd Intermediate CA
```

<details>

### Create the intermediate certificate

Use the intermediate key to create a certificate signing request (CSR). The details should generally match the root CA. The Common Name, however, must be different.

> Warning: Make sure you specify the intermediate CA configuration file (`intermediate/openssl.cnf`).

```
cd /root/ca
openssl req -config intermediate/openssl.cnf -new -sha256 \
      -key intermediate/private/intermediate.key.pem -out intermediate/csr/intermediate.csr.pem

Enter pass phrase for intermediate.key.pem: secretpassword
You are about to be asked to enter information that will be incorporated
into your certificate request.
-----
Country Name (2 letter code) [XX]:GB
State or Province Name []:England
Locality Name []:
Organization Name []:Alice Ltd
Organizational Unit Name []:Alice Ltd Certificate Authority
Common Name []:Alice Ltd Intermediate CA
Email Address []:
```

To create an intermediate certificate, use the root CA with the `v3_intermediate_ca` extension to sign the intermediate CSR. The intermediate certificate should be valid for a shorter period than the root certificate. Ten years would be reasonable.

> Warning: This time, specify the root CA configuration file (`/root/ca/openssl.cnf`).

```
cd /root/ca
openssl ca -config openssl.cnf -extensions v3_intermediate_ca -days 3650 -notext -md sha256 \
      -in intermediate/csr/intermediate.csr.pem -out intermediate/certs/intermediate.cert.pem

Enter pass phrase for ca.key.pem: secretpassword
Sign the certificate? [y/n]: y

chmod 444 intermediate/certs/intermediate.cert.pem
```

The `index.txt` file is where the OpenSSL `ca` tool stores the certificate database. Do not delete or edit this file by hand. It should now contain a line that refers to the intermediate certificate.

```
V 250408122707Z 1000 unknown ... /CN=Alice Ltd Intermediate CA
```

</details>

### Ara Sertifikayı Doğrulayın

Kök sertifika için yaptığımız gibi ara sertifikanın ayrıntılarının doğru olup olmadığını kontrol edin.

```
openssl x509 -noout -text -in intermediate/certs/intermediate.cert.pem
```

Kök sertifika ile ara sertifikayı doğrulayın. "OK" çıktısı, güven zincirinin sağlam olduğunu gösterir.

```
openssl verify -CAfile certs/ca.cert.pem intermediate/certs/intermediate.cert.pem

intermediate.cert.pem: OK
```

<details>

### Verify the intermediate certificate

As we did for the root certificate, check that the details of the intermediate certificate are correct.

```
openssl x509 -noout -text -in intermediate/certs/intermediate.cert.pem
```

Verify the intermediate certificate against the root certificate. An `OK` indicates that the chain of trust is intact.

```
openssl verify -CAfile certs/ca.cert.pem intermediate/certs/intermediate.cert.pem

intermediate.cert.pem: OK
```
</details>

### Sertifika Zinciri Dosyası Oluşturun (ca-chain.cert.pem)

Bir uygulama (örneğin bir web tarayıcısı) ara CA tarafından imzalanmış bir sertifikayı doğrulamaya çalıştığında, oda kök sertifika ile ara sertifikayı doğrulayabilmelidir. Güven zincirini tamamlamak için, uygulamaya sunulacak bir CA sertifika zinciri oluşturun.

CA sertifika zincirini oluşturmak için, ara ve kök sertifikaları bir araya getirin. Bu dosyayı daha sonra ara CA tarafından imzalanmış sertifikaları doğrulamak için kullanacağız.

```
cat intermediate/certs/intermediate.cert.pem certs/ca.cert.pem > intermediate/certs/ca-chain.cert.pem
chmod 444 intermediate/certs/ca-chain.cert.pem
```

> Not: İstemciler, kök sertifikayı bilmediği için sertifika zinciri dosyamız kök sertifikayı da içermelidir. Daha iyi bir seçenek, özellikle bir intraneti yönetiyorsanız, kök sertifikanızı bütün istemcilere yüklemektir. Bu durumda, zincir dosyasının yalnızca ara sertifika içermesi yeterlidir.


<details>
### Create the certificate chain file

When an application (eg, a web browser) tries to verify a certificate signed by the intermediate CA, it must also verify the intermediate certificate against the root certificate. To complete the chain of trust, create a CA certificate chain to present to the application.

To create the CA certificate chain, concatenate the intermediate and root certificates together. We will use this file later to verify certificates signed by the intermediate CA.

```
cat intermediate/certs/intermediate.cert.pem certs/ca.cert.pem > intermediate/certs/ca-chain.cert.pem
chmod 444 intermediate/certs/ca-chain.cert.pem
```

> Note: Our certificate chain file must include the root certificate because no client application knows about it yet. A better option, particularly if you’re administrating an intranet, is to install your root certificate on every client that needs to connect. In that case, the chain file need only contain your intermediate certificate.
</details>

## Sunucu ve İstemci Sertifikalarını İmzalayın

Şimdi Ara CA'nızı kullanarak sertifika imzalayacağız. Bu imzalı sertifikaları, bir web sunucusuna olan bağlantıları güvenli kılmak veya bir servise bağlanan istemcileri doğrulamak gibi çeşitli durumlarda kullanabilirsiniz.

> Not: Aşağıdaki adımlar, sertifika yetkilisi olarak uyguladığımız bir bakış açısının sonucudur. Bu bakış açısının yerine, istemci kendi özel anahtarını ve sertifika imzalama isteğini (CSR) kendi anahtarını size göstermeden oluşturabilir. Size kendi CSR'ını verirler ve sizde imzalı bir sertifikayı geri verirsiniz. Böyle bir durumda senaryoda `genrsa` ve` req` komutlarını atlayabilirsiniz.

<details>
## Sign server and client certificates

We will be signing certificates using our intermediate CA. You can use these signed certificates in a variety of situations, such as to secure connections to a web server or to authenticate clients connecting to a service.

> Note: The steps below are from your perspective as the certificate authority. A third-party, however, can instead create their own private key and certificate signing request (CSR) without revealing their private key to you. They give you their CSR, and you give back a signed certificate. In that scenario, skip the `genrsa` and `req` commands.
</details>

### Bir Anahtar Oluşturun

Kök ve ara çiftlerimiz 4096 bittir. Sunucu ve istemci sertifikaları normalde bir yıl sonra sona erecek, bu sebeple sunucu ve istemci için 2048 biti güvenle kullanabilirsiniz.

> Not: 4096 bit, 2048 bitten biraz daha güvenli olmasına rağmen, TLS doğrulamasını yavaşlatır ve doğrulama sırasında işlemci yükünü önemli ölçüde artırır. Bu nedenle çoğu web sitesi 2048 bitlik çift kullanır.

Bir web sunucusu (ör. Apache) ile kullanılacak şifreleme çifti oluşturuyorsanız, web sunucusunu her yeniden başlattığınızda bu şifreyi girmeniz gerekecektir. Parolasız bir anahtar oluşturmak için `-aes256` seçeneğini çıkartmak isteyebilirsiniz.

```
cd /root/ca
openssl genrsa -aes256 -out intermediate/private/www.example.com.key.pem 2048
chmod 400 intermediate/private/www.example.com.key.pem
```

<details>
### Create a key

Our root and intermediate pairs are 4096 bits. Server and client certificates normally expire after one year, so we can safely use 2048 bits instead.

> Note: Although 4096 bits is slightly more secure than 2048 bits, it slows down TLS handshakes and significantly increases processor load during handshakes. For this reason, most websites use 2048-bit pairs.

If you’re creating a cryptographic pair for use with a web server (eg, Apache), you’ll need to enter this password every time you restart the web server. You may want to omit the `-aes256` option to create a key without a password.

```
cd /root/ca
openssl genrsa -aes256 -out intermediate/private/www.example.com.key.pem 2048
chmod 400 intermediate/private/www.example.com.key.pem
```
</details>

### Bir Sertifika Oluşturun

Bir sertifika imzalama isteği (CSR) oluşturmak için özel anahtar kullanın. CSR ayrıntılarının ara CA ile eşleşmesi gerekmez. Sunucu sertifikaları için, Ortak Ad (**Common Name**), bir tam nitelikli alan adı (ör. 'www.example.com') olmalıdır, oysa istemci sertifikaları için herhangi bir benzersiz tanımlayıcı (ör. Bir e-posta adresi) olabilir. Ortak Adın, kök veya ara sertifikanızla aynı __olamayacağına__ dikkat edin.

```
cd /root/ca
openssl req -config intermediate/openssl.cnf \
      -key intermediate/private/www.example.com.key.pem -new -sha256 -out intermediate/csr/www.example.com.csr.pem

Enter pass phrase for www.example.com.key.pem: secretpassword
You are about to be asked to enter information that will be incorporated
into your certificate request.
-----
Country Name (2 letter code) [XX]:US
State or Province Name []:California
Locality Name []:Mountain View
Organization Name []:Alice Ltd
Organizational Unit Name []:Alice Ltd Web Services
Common Name []:www.example.com
Email Address []:
```

CSR'yi imzalamak için ara CA'yı kullanın ve sertifika oluşturun. Sertifika bir sunucuda kullanılacaksa, `server_cert` uzantısını kullanın. Sertifika kullanıcı kimlik doğrulaması için kullanılacak ise, `usr_cert` uzantısını kullanın. Bu sertifikalara genellikle bir yıl geçerliliği verilir ancak kolaylık sağlamak için sertfika yetkilisi CA ekstra bir kaç gün daha verir.

```
cd /root/ca
openssl ca -config intermediate/openssl.cnf -extensions server_cert -days 375 -notext -md sha256 \
      -in intermediate/csr/www.example.com.csr.pem -out intermediate/certs/www.example.com.cert.pem
chmod 444 intermediate/certs/www.example.com.cert.pem
```

`intermediate/index.txt` dosyası bu yeni sertifikaya atıf yapan bir satır içermelidir.

```
V 160420124233Z 1000 unknown ... /CN=www.example.com
```

<details>
### Create a certificate

Use the private key to create a certificate signing request (CSR). The CSR details don’t need to match the intermediate CA. For server certificates, the Common Name must be a fully qualified domain name (eg, `www.example.com`), whereas for client certificates it can be any unique identifier (eg, an e-mail address). Note that the Common Name cannot be the same as either your root or intermediate certificate.

```
cd /root/ca
openssl req -config intermediate/openssl.cnf -key intermediate/private/www.example.com.key.pem \
      -new -sha256 -out intermediate/csr/www.example.com.csr.pem

Enter pass phrase for www.example.com.key.pem: secretpassword
You are about to be asked to enter information that will be incorporated
into your certificate request.
-----
Country Name (2 letter code) [XX]:US
State or Province Name []:California
Locality Name []:Mountain View
Organization Name []:Alice Ltd
Organizational Unit Name []:Alice Ltd Web Services
Common Name []:www.example.com
Email Address []:
```

To create a certificate, use the intermediate CA to sign the CSR. If the certificate is going to be used on a server, use the `server_cert` extension. If the certificate is going to be used for user authentication, use the `usr_cert` extension. Certificates are usually given a validity of one year, though a CA will typically give a few days extra for convenience.

```
cd /root/ca
openssl ca -config intermediate/openssl.cnf -extensions server_cert -days 375 -notext -md sha256 \
      -in intermediate/csr/www.example.com.csr.pem -out intermediate/certs/www.example.com.cert.pem
chmod 444 intermediate/certs/www.example.com.cert.pem
```

The `intermediate/index.txt` file should contain a line referring to this new certificate.

```
V 160420124233Z 1000 unknown ... /CN=www.example.com
```

</details>

### Sertifikayı Doğrulayın

```
openssl x509 -noout -text -in intermediate/certs/www.example.com.cert.pem
```

Sağlayıcı(Issuer) ara CA'dır. Konu sertifikanın kendisiyle ilgilidir.

```
Signature Algorithm: sha256WithRSAEncryption
    Issuer: C=GB, ST=England,
            O=Alice Ltd, OU=Alice Ltd Certificate Authority,
            CN=Alice Ltd Intermediate CA
    Validity
        Not Before: Apr 11 12:42:33 2015 GMT
        Not After : Apr 20 12:42:33 2016 GMT
    Subject: C=US, ST=California, L=Mountain View,
             O=Alice Ltd, OU=Alice Ltd Web Services,
             CN=www.example.com
    Subject Public Key Info:
        Public Key Algorithm: rsaEncryption
            Public-Key: (2048 bit)
```

Çıktı X509v3 uzantılarını da gösterecektir. Sertifika oluşturulurken, `server_cert` veya `usr_cert` uzantısını kullandınız. İlgili yapılandırma bölümündeki seçenekler çıktı ekranına yansıtılacaktır.

```
X509v3 extensions:
    X509v3 Basic Constraints:
        CA:FALSE
    Netscape Cert Type:
        SSL Server
    Netscape Comment:
        OpenSSL Generated Server Certificate
    X509v3 Subject Key Identifier:
        B1:B8:88:48:64:B7:45:52:21:CC:35:37:9E:24:50:EE:AD:58:02:B5
    X509v3 Authority Key Identifier:
        keyid:69:E8:EC:54:7F:25:23:60:E5:B6:E7:72:61:F1:D4:B9:21:D4:45:E9
        DirName:/C=GB/ST=England/O=Alice Ltd/OU=Alice Ltd Certificate Authority/CN=Alice Ltd Root CA
        serial:10:00

    X509v3 Key Usage: critical
        Digital Signature, Key Encipherment
    X509v3 Extended Key Usage:
        TLS Web Server Authentication
```

Yeni sertifikanın geçerli bir güven zincirine sahip olduğunu doğrulamak için daha önce oluşturduğumuz CA sertifika zinciri dosyasını kullanın (`ca-chain.cert.pem`).

```
openssl verify -CAfile intermediate/certs/ca-chain.cert.pem intermediate/certs/www.example.com.cert.pem

www.example.com.cert.pem: OK
```

<details>
### Verify the certificate

```
openssl x509 -noout -text -in intermediate/certs/www.example.com.cert.pem
```

The Issuer is the intermediate CA. The Subject refers to the certificate itself.

```
Signature Algorithm: sha256WithRSAEncryption
    Issuer: C=GB, ST=England,
            O=Alice Ltd, OU=Alice Ltd Certificate Authority,
            CN=Alice Ltd Intermediate CA
    Validity
        Not Before: Apr 11 12:42:33 2015 GMT
        Not After : Apr 20 12:42:33 2016 GMT
    Subject: C=US, ST=California, L=Mountain View,
             O=Alice Ltd, OU=Alice Ltd Web Services,
             CN=www.example.com
    Subject Public Key Info:
        Public Key Algorithm: rsaEncryption
            Public-Key: (2048 bit)
```

The output will also show the X509v3 extensions. When creating the certificate, you used either the `server_cert` or `usr_cert` extension. The options from the corresponding configuration section will be reflected in the output.

```
X509v3 extensions:
    X509v3 Basic Constraints:
        CA:FALSE
    Netscape Cert Type:
        SSL Server
    Netscape Comment:
        OpenSSL Generated Server Certificate
    X509v3 Subject Key Identifier:
        B1:B8:88:48:64:B7:45:52:21:CC:35:37:9E:24:50:EE:AD:58:02:B5
    X509v3 Authority Key Identifier:
        keyid:69:E8:EC:54:7F:25:23:60:E5:B6:E7:72:61:F1:D4:B9:21:D4:45:E9
        DirName:/C=GB/ST=England/O=Alice Ltd/OU=Alice Ltd Certificate Authority/CN=Alice Ltd Root CA
        serial:10:00

    X509v3 Key Usage: critical
        Digital Signature, Key Encipherment
    X509v3 Extended Key Usage:
        TLS Web Server Authentication
```

Use the CA certificate chain file we created earlier (`ca-chain.cert.pem`) to verify that the new certificate has a valid chain of trust.

```
openssl verify -CAfile intermediate/certs/ca-chain.cert.pem intermediate/certs/www.example.com.cert.pem

www.example.com.cert.pem: OK
```
</details>

### Sertifikayı Yayınlayın

Artık yeni sertifikanızı bir sunucuya veya istemciye dağıtabilirsiniz. Bir sunucu uygulamasına (örneğin, Apache) dağıtırken aşağıdaki dosyaları hazır bulundurmanız gerekir:

* `ca-chain.cert.pem`
* `www.example.com.key.pem`
* `www.example.com.cert.pem`

Üçüncü taraftan bir CSR imzalıyorsanız, özel anahtarlarına erişemezsiniz, bu nedenle yalnızca zincir dosyasına (`ca-chain.cert.pem`) ve sertifikaya (`www.example.com.cert.pem`) sahip olacaksınız.

<details>

### Deploy the certificate

You can now either deploy your new certificate to a server, or distribute the certificate to a client. When deploying to a server application (eg, Apache), you need to make the following files available:

* `ca-chain.cert.pem`
* `www.example.com.key.pem`
* `www.example.com.cert.pem`

If you’re signing a CSR from a third-party, you don’t have access to their private key so you only need to give them back the chain file (`ca-chain.cert.pem`) and the certificate (`www.example.com.cert.pem`).
</details>

## Sertifika İptal Listeleri

Bir sertifika iptal listesi (CRL), iptal edilen sertifikaların bir listesini sağlar. Web tarayıcısı gibi bir istemci uygulaması, bir sunucunun doğruluğunu kontrol etmek için bir CRL kullanabilir. Apache veya OpenVPN gibi bir sunucu uygulaması, artık güvenilmeyen istemcilere erişimi reddetmek için bir CRL kullanabilir.

CRL'yi herkes tarafından erişilebilir bir adreste yayınlayın (ör. `http://example.com/intermediate.crl.pem`). Üçüncü taraflar, güvenilen herhangi bir sertifikanın iptal edilip edilmediğini kontrol etmek için CRL'yi bu adresten alabilirler.

> Not: Bazı uygulama sağlayıcıları CRL'ler yerine Çevrimiçi Sertifika Durum Protokolü'nü (OCSP) kullanmaktadır.

<details>
## Certificate revocation lists

A certificate revocation list (CRL) provides a list of certificates that have been revoked. A client application, such as a web browser, can use a CRL to check a server’s authenticity. A server application, such as Apache or OpenVPN, can use a CRL to deny access to clients that are no longer trusted.

Publish the CRL at a publicly accessible location (eg, `http://example.com/intermediate.crl.pem`). Third-parties can fetch the CRL from this location to check whether any certificates they rely on have been revoked.

> Note: Some applications vendors have deprecated CRLs and are instead using the Online Certificate Status Protocol (OCSP).
</details>

### Yapılandırma Dosyasını Hazırlayın

Bir sertifika yetkilisi bir sertifikayı imzaladığında, normalde CRL konumunu sertifikaya kodlar. Uygun bölümlere `crlDistributionPoints` ekleyin. Bizim durumumuzda, `[server_cert]` bölümüne ekleyin.

```
[ server_cert ]
# ... snipped ...
crlDistributionPoints = URI:http://example.com/intermediate.crl.pem
```

<details>

### Prepare the configuration file

When a certificate authority signs a certificate, it will normally encode the CRL location into the certificate. Add `crlDistributionPoints` to the appropriate sections. In our case, add it to the `[ server_cert ]` section.

```
[ server_cert ]
# ... snipped ...
crlDistributionPoints = URI:http://example.com/intermediate.crl.pem
```
</details>

### CRL'yi Oluşturun

```
cd /root/ca
openssl ca -config intermediate/openssl.cnf -gencrl -out intermediate/crl/intermediate.crl.pem
```

> Not: `ca` man sayfasının `CRL OPTIONS` bölümü, CRL'lerin nasıl oluşturulacağı hakkında daha fazla bilgi içerir.

CRL içeriğini `crl` aracı ile kontrol edebilirsiniz.

```
openssl crl -in intermediate/crl/intermediate.crl.pem -noout -text
```

Hiçbir sertifika iptal edilmedi, bu nedenle çıktıda `No Revoked Certificates` ifadesi mevcut.

CRL'yi düzenli aralıklarla yeniden oluşturmalısınız. Varsayılan olarak, CRL 30 gün sonra sona erer. Bu, `[CA_default]` bölümündeki `default_crl_days` seçeneği ile kontrol edilir.

<details>

### Create the CRL

```
cd /root/ca
openssl ca -config intermediate/openssl.cnf -gencrl -out intermediate/crl/intermediate.crl.pem
```

> Note: The `CRL OPTIONS` section of the `ca` man page contains more information on how to create CRLs.

You can check the contents of the CRL with the `crl` tool.

```
openssl crl -in intermediate/crl/intermediate.crl.pem -noout -text
```

No certificates have been revoked yet, so the output will state `No Revoked Certificates`.

You should re-create the CRL at regular intervals. By default, the CRL expires after 30 days. This is controlled by the `default_crl_days` option in the `[ CA_default ]` section.
</details>

### Bir Sertifikayı İptal Edin

Bir örnek üzerinden yürüyelim. Alice'in özel, sevimli kedi resimleri içeren koleksiyonu var. Bu koleksiyon, Apache web sunucusu üzerinde yayınlanıyor ve Alice, arkadaşı Bob'a bu koleksiyona bakabilmesi için erişim izni vermek istiyor.

Bu durumda Bob özel bir anahtar ve sertifika imzalama isteği (CSR) oluşturur.

```
cd /home/bob
openssl genrsa -out bob@example.com.key.pem 2048
openssl req -new -key bob@example.com.key.pem -out bob@example.com.csr.pem

You are about to be asked to enter information that will be incorporated
into your certificate request.
-----
Country Name [XX]:US
State or Province Name []:California
Locality Name []:San Francisco
Organization Name []:Bob Ltd
Organizational Unit Name []:
Common Name []:bob@example.com
Email Address []:
```

Bob CSR'sini Alice'e gönderir ve Alice imzalar.

```
cd /root/ca
openssl ca -config intermediate/openssl.cnf -extensions usr_cert -notext -md sha256 \
      -in intermediate/csr/bob@example.com.csr.pem -out intermediate/certs/bob@example.com.cert.pem

Sign the certificate? [y/n]: y
1 out of 1 certificate requests certified, commit? [y/n]: y
```

Alice sertifikanın geçerliliğini doğrular:

```
openssl verify -CAfile intermediate/certs/ca-chain.cert.pem intermediate/certs/bob@example.com.cert.pem

bob@example.com.cert.pem: OK
```

`index.txt` dosyası yeni bir girdi içermelidir.

```
V 160420124740Z 1001 unknown ... /CN=bob@example.com
```

Alice imzalı sertifikayı Bob'a gönderir. Bob sertifika web tarayıcısına yükler ve artık Alice'in yavru kedi resimlerine erişebilir. Harika!

Maalesef bir süre sonra, Bob'un yanlış davranıldığı anlaşılıyor. Bob, Alice'in yavru kedi resimlerini Hacker News'e gönderdi ve kendisine ait olduklarını iddia etti. Alice durumu öğrendikten sonra derhal Bob'un erişimini iptal etmesi gerekir.

```
cd /root/ca
openssl ca -config intermediate/openssl.cnf -revoke intermediate/certs/bob@example.com.cert.pem

Enter pass phrase for intermediate.key.pem: secretpassword
Revoking Certificate 1001.
Data Base Updated
```

`index.text` içindeki Bob'un sertifikasına karşılık gelen satır artık `R` karakteriyle başlar. Bu, sertifikanın iptal edildiği anlamına gelir.

```
R 160420124740Z 150411125310Z 1001 unknown ... /CN=bob@example.com
```

Bob'un sertifikasını iptal ettikten sonra, Alice CRL'yi yeniden oluşturmalıdır.

<details>
### Revoke a certificate

Let’s walk through an example. Alice is running the Apache web server and has a private folder of heart-meltingly cute kitten pictures. Alice wants to grant her friend, Bob, access to this collection.

Bob creates a private key and certificate signing request (CSR).

```
cd /home/bob
openssl genrsa -out bob@example.com.key.pem 2048
openssl req -new -key bob@example.com.key.pem \
      -out bob@example.com.csr.pem

You are about to be asked to enter information that will be incorporated
into your certificate request.
-----
Country Name [XX]:US
State or Province Name []:California
Locality Name []:San Francisco
Organization Name []:Bob Ltd
Organizational Unit Name []:
Common Name []:bob@example.com
Email Address []:
```

Bob sends his CSR to Alice, who then signs it.

```
cd /root/ca
openssl ca -config intermediate/openssl.cnf -extensions usr_cert -notext -md sha256 \
      -in intermediate/csr/bob@example.com.csr.pem -out intermediate/certs/bob@example.com.cert.pem

Sign the certificate? [y/n]: y
1 out of 1 certificate requests certified, commit? [y/n]: y
```

Alice verifies that the certificate is valid:

```
openssl verify -CAfile intermediate/certs/ca-chain.cert.pem intermediate/certs/bob@example.com.cert.pem

bob@example.com.cert.pem: OK
```

The `index.txt` file should contain a new entry.

```
V 160420124740Z 1001 unknown ... /CN=bob@example.com
```

Alice sends Bob the signed certificate. Bob installs the certificate in his web browser and is now able to access Alice’s kitten pictures. Hurray!

Sadly, it turns out that Bob is misbehaving. Bob has posted Alice’s kitten pictures to Hacker News, claiming that they’re his own and gaining huge popularity. Alice finds out and needs to revoke his access immediately.

```
cd /root/ca
openssl ca -config intermediate/openssl.cnf -revoke intermediate/certs/bob@example.com.cert.pem

Enter pass phrase for intermediate.key.pem: secretpassword
Revoking Certificate 1001.
Data Base Updated
```

The line in `index.txt` that corresponds to Bob’s certificate now begins with the character `R`. This means the certificate has been revoked.

```
R 160420124740Z 150411125310Z 1001 unknown ... /CN=bob@example.com
```

After revoking Bob’s certificate, Alice must re-create the CRL.
</details>

### CRL'nin Sunucu Tarafında Kullanımı

İstemci sertifikaları için, doğrulamayı yapan bir sunucu taraflı uygulama (örn. Apache) olur. Bu uygulamanın CRL'ye yerel erişimi olmalıdır.

Alice'in durumunda, Apache yapılandırmasına 'SSLCARevocationPath' yönergesini ekleyebilir ve CRL'yi web sunucusuna kopyalayabilir. Bob, bir dahaki sefere Web sunucusuna bağlandığında Apache, istemci sertifikasını CRL'ye karşı kontrol eder ve erişimi reddeder.

Benzer bir şekilde, OpenVPN sertifikalarını iptal eden istemcileri engelleyebilmek için bir `crl-verify` yönergesine sahiptir.

<details>

### Server-side use of the CRL

For client certificates, it’s typically a server-side application (eg, Apache) that is doing the verification. This application needs to have local access to the CRL.

In Alice’s case, she can add the `SSLCARevocationPath` directive to her Apache configuration and copy the CRL to her web server. The next time that Bob connects to the web server, Apache will check his client certificate against the CRL and deny access.

Similarly, OpenVPN has a `crl-verify` directive so that it can block clients that have had their certificates revoked.
</details>


### CRL'nin İstemci Tarafında Kullanımı

Sunucu sertifikaları için, doğrulama işlemini gerçekleştiren bir istemci tarafı uygulaması (örn. Bir web tarayıcı) olur. Bu uygulamanın CRL'ye uzaktan erişimi olmalıdır.

Bir sertifika, 'crlDistributionPoints' içeren bir uzantıyla imzalanmışsa, istemci tarafılı bir uygulama bu bilgiyi okuyabilir ve CRL'yi belirtilen konumdan getirir.

CRL dağıtım noktaları, X509v3 sertifikasında ayrıntılı olarak görülebilir.

```
openssl x509 -in cute-kitten-pictures.example.com.cert.pem -noout -text

    X509v3 CRL Distribution Points:

        Full Name:
          URI:http://example.com/intermediate.crl.pem
```

<details>
### Client-side use of the CRL

For server certificates, it’s typically a client-side application (eg, a web browser) that performs the verification. This application must have remote access to the CRL.

If a certificate was signed with an extension that includes `crlDistributionPoints`, a client-side application can read this information and fetch the CRL from the specified location.

The CRL distribution points are visible in the certificate X509v3 details.

```
openssl x509 -in cute-kitten-pictures.example.com.cert.pem -noout -text

    X509v3 CRL Distribution Points:

        Full Name:
          URI:http://example.com/intermediate.crl.pem
```
</details>

## Çevrimiçi Sertifika Durumu Protokolü

Çevrimiçi Sertifika Durumu Protokolü (OCSP), sertifika iptal listelerine (CRL) alternatif olarak oluşturuldu. CRL'lere benzer şekilde, OCSP, bir sertifika iptal durumunu belirlemek için istek yapan tarafın (örneğin, bir web tarayıcısı) olmasını sağlar.

Bir CA; sertifika imzaladığında, sertifikaya genellikle bir OCSP sunucu adresi (örn., `http://ocsp.example.com`) ekleyecektir. Bu işlevde CRL'lerde kullanılan `crlDistributionPoints` ile benzerdir.

Örnek olarak, bir web tarayıcısı bir sunucu sertifikasıyla sunulduğunda, sertifikada belirtilen OCSP sunucu adresine bir sorgu gönderecektir. Bu adreste OCSP, sorguları dinler ve sertifikanın iptal durumuyla ilgili yanıtı verir.

> Not: Mümkün olduğunca OCSP kullanmanız önerilir, genelde web sitesi sertifikaları için OCSP'ye gereksinim duyacaksınız. Bazı web tarayıcıları, CRL desteğini kullanımdan kaldırmıştır.

<details>
## Online Certificate Status Protocol

The Online Certificate Status Protocol (OCSP) was created as an alternative to certificate revocation lists (CRLs). Similar to CRLs, OCSP enables a requesting party (eg, a web browser) to determine the revocation state of a certificate.

When a CA signs a certificate, they will typically include an OCSP server address (eg, `http://ocsp.example.com`) in the certificate. This is similar in function to `crlDistributionPoints` used for CRLs.

As an example, when a web browser is presented with a server certificate, it will send a query to the OCSP server address specified in the certificate. At this address, an OCSP responder listens to queries and responds with the revocation status of the certificate.

> Note: It’s recommended to use OCSP instead where possible, though realistically you will tend to only need OCSP for website certificates. Some web browsers have deprecated or removed support for CRLs.
</details>

### Yapılandırma Dosyasını Hazırlayın

OCSP'yi kullanmak için CA, OCSP sunucu konumunu imzaladığı sertifikalara kodlamalıdır. Bizim durumumuzda `[server_cert]` bölümünde  `authorityInfoAccess` seçeneğini kullanın.

```
[ server_cert ]
# ... snipped ...
authorityInfoAccess = OCSP;URI:http://ocsp.example.com
```

<details>
### Prepare the configuration file

To use OCSP, the CA must encode the OCSP server location into the certificates that it signs. Use the `authorityInfoAccess` option in the appropriate sections, which in our case means the `[ server_cert ]` section.

```
[ server_cert ]
# ... snipped ...
authorityInfoAccess = OCSP;URI:http://ocsp.example.com
```
</details>

### OCSP Çifti Oluşturun

OCSP yanıtlayıcı, istekte bulunan kişiye gönderdiği yanıtı imzalamak için bir şifreleme çiftine ihtiyaç duyar. OCSP şifreleme çifti, kontrol edilen sertifikayı imzalayan aynı CA tarafından imzalanmış olmalıdır.

Özel bir anahtar oluşturun ve AES-256 şifrelemesi ile şifreleyin.

```
cd /root/ca
openssl genrsa -aes256 -out intermediate/private/ocsp.example.com.key.pem 4096
```

Bir sertifika imzalama isteği (CSR) oluşturun. Ayrıntılar genellikle imzalayan CA ile eşleşmelidir. Bununla birlikte, Ortak Ad (**Common Name**) tam bir alan adı olmalıdır.

```
cd /root/ca
openssl req -config intermediate/openssl.cnf -new -sha256 -key intermediate/private/ocsp.example.com.key.pem \
      -out intermediate/csr/ocsp.example.com.csr.pem

Enter pass phrase for intermediate.key.pem: secretpassword
You are about to be asked to enter information that will be incorporated
into your certificate request.
-----
Country Name (2 letter code) [XX]:GB
State or Province Name []:England
Locality Name []:
Organization Name []:Alice Ltd
Organizational Unit Name []:Alice Ltd Certificate Authority
Common Name []:ocsp.example.com
Email Address []:
```

CSR'yi ara CA ile imzalayın.

```
openssl ca -config intermediate/openssl.cnf -extensions ocsp -days 375 -notext -md sha256 \
      -in intermediate/csr/ocsp.example.com.csr.pem -out intermediate/certs/ocsp.example.com.cert.pem
```

Sertifikanın doğru X509v3 uzantılarına sahip olduğunu doğrulayın.

```
openssl x509 -noout -text -in intermediate/certs/ocsp.example.com.cert.pem

    X509v3 Key Usage: critical
        Digital Signature
    X509v3 Extended Key Usage: critical
        OCSP Signing
```

<details>
### Create the OCSP pair

The OCSP responder requires a cryptographic pair for signing the response that it sends to the requesting party. The OCSP cryptographic pair must be signed by the same CA that signed the certificate being checked.

Create a private key and encrypt it with AES-256 encryption.

```
cd /root/ca
openssl genrsa -aes256 -out intermediate/private/ocsp.example.com.key.pem 4096
```

Create a certificate signing request (CSR). The details should generally match those of the signing CA. The Common Name, however, must be a fully qualified domain name.

```
cd /root/ca
openssl req -config intermediate/openssl.cnf -new -sha256 -key intermediate/private/ocsp.example.com.key.pem \
      -out intermediate/csr/ocsp.example.com.csr.pem

Enter pass phrase for intermediate.key.pem: secretpassword
You are about to be asked to enter information that will be incorporated
into your certificate request.
-----
Country Name (2 letter code) [XX]:GB
State or Province Name []:England
Locality Name []:
Organization Name []:Alice Ltd
Organizational Unit Name []:Alice Ltd Certificate Authority
Common Name []:ocsp.example.com
Email Address []:
```

Sign the CSR with the intermediate CA.

```
openssl ca -config intermediate/openssl.cnf -extensions ocsp -days 375 -notext -md sha256 \
      -in intermediate/csr/ocsp.example.com.csr.pem -out intermediate/certs/ocsp.example.com.cert.pem
```

Verify that the certificate has the correct X509v3 extensions.

```
openssl x509 -noout -text -in intermediate/certs/ocsp.example.com.cert.pem

    X509v3 Key Usage: critical
        Digital Signature
    X509v3 Extended Key Usage: critical
        OCSP Signing
```
</details>

### Bir Sertifikayı İptal Edin

OpenSSL'in `ocsp` aracı bir OCSP cevaplayıcı olarak görev yapabilir, ancak sadece test amaçlıdır. Çerçek yayın ortamı (prodcution) için hazır OCSP yeteneklerine sahiptir, ancak bunlar bu kılavuzun kapsamı dışındadır.

Sınamak için bir sunucu sertifikası oluşturun.

```
cd /root/ca
openssl genrsa -out intermediate/private/test.example.com.key.pem 2048
openssl req -config intermediate/openssl.cnf -key intermediate/private/test.example.com.key.pem \
      -new -sha256 -out intermediate/csr/test.example.com.csr.pem
openssl ca -config intermediate/openssl.cnf -extensions server_cert -days 375 -notext -md sha256 \
      -in intermediate/csr/test.example.com.csr.pem \
      -out intermediate/certs/test.example.com.cert.pem
```

OCSP cevaplayıcıyı `localhost` üzerinde çalıştırın. İptalin durumunu ayrı bir CRL dosyasına kaydetmek yerine OCSP yanıtlayıcı `index.txt` dosyasını doğrudan okur. Yanıt OCSP şifreleme çifti ile imzalanmıştır (`-rkey` ve` -rsigner` seçenekleri kullanılarak).

```
openssl ocsp -port 127.0.0.1:2560 -text -sha256 -index intermediate/index.txt -CA intermediate/certs/ca-chain.cert.pem \
      -rkey intermediate/private/ocsp.example.com.key.pem \
      -rsigner intermediate/certs/ocsp.example.com.cert.pem \
      -nrequest 1

Enter pass phrase for ocsp.example.com.key.pem: secretpassword
```

Başka bir terminalde, OCSP yanıtlayıcısına bir sorgu gönderin. `-cert` seçeneği, sorgulanacak sertifikayı belirtir.

```
openssl ocsp -CAfile intermediate/certs/ca-chain.cert.pem -url http://127.0.0.1:2560 -resp_text \
      -issuer intermediate/certs/intermediate.cert.pem \
      -cert intermediate/certs/test.example.com.cert.pem
```

Çıktının başlangıcını şöyledir:

* Başarılı bir cevap alındı mı ("OCSP Response Status")
* Yanıtlayıcı kimliği ('Responder Id')
* Sertifikanın iptal durumu ("Cert Status")

```
OCSP Response Data:
    OCSP Response Status: successful (0x0)
    Response Type: Basic OCSP Response
    Version: 1 (0x0)
    Responder Id: ... CN = ocsp.example.com
    Produced At: Apr 11 12:59:51 2015 GMT
    Responses:
    Certificate ID:
      Hash Algorithm: sha1
      Issuer Name Hash: E35979B6D0A973EBE8AEDED75D8C27D67D2A0334
      Issuer Key Hash: 69E8EC547F252360E5B6E77261F1D4B921D445E9
      Serial Number: 1003
    Cert Status: good
    This Update: Apr 11 12:59:51 2015 GMT
```

Sertifikayı iptal et.

```
openssl ca -config intermediate/openssl.cnf -revoke intermediate/certs/test.example.com.cert.pem

Enter pass phrase for intermediate.key.pem: secretpassword
Revoking Certificate 1003.
Data Base Updated
```

Daha önce olduğu gibi, OCSP yanıtlayıcıyı çalıştırın ve başka bir terminalde bir sorgu gönderin. Bu sefer, çıktıda 'Cert Status: revoked' ve 'Revocation Time' elde edilecektir.

```
OCSP Response Data:
    OCSP Response Status: successful (0x0)
    Response Type: Basic OCSP Response
    Version: 1 (0x0)
    Responder Id: ... CN = ocsp.example.com
    Produced At: Apr 11 13:03:00 2015 GMT
    Responses:
    Certificate ID:
      Hash Algorithm: sha1
      Issuer Name Hash: E35979B6D0A973EBE8AEDED75D8C27D67D2A0334
      Issuer Key Hash: 69E8EC547F252360E5B6E77261F1D4B921D445E9
      Serial Number: 1003
    Cert Status: revoked
    Revocation Time: Apr 11 13:01:09 2015 GMT
    This Update: Apr 11 13:03:00 2015 GMT
```

<details>
### Revoke a certificate

The OpenSSL `ocsp` tool can act as an OCSP responder, but it’s only intended for testing. Production ready OCSP responders exist, but those are beyond the scope of this guide.

Create a server certificate to test.

```
cd /root/ca
openssl genrsa -out intermediate/private/test.example.com.key.pem 2048
openssl req -config intermediate/openssl.cnf -key intermediate/private/test.example.com.key.pem \
      -new -sha256 -out intermediate/csr/test.example.com.csr.pem
openssl ca -config intermediate/openssl.cnf -extensions server_cert -days 375 -notext -md sha256 \
      -in intermediate/csr/test.example.com.csr.pem \
      -out intermediate/certs/test.example.com.cert.pem
```

Run the OCSP responder on `localhost`. Rather than storing revocation status in a separate CRL file, the OCSP responder reads `index.txt` directly. The response is signed with the OCSP cryptographic pair (using the `-rkey` and `-rsigner` options).

```
openssl ocsp -port 127.0.0.1:2560 -text -sha256 -index intermediate/index.txt -CA intermediate/certs/ca-chain.cert.pem \
      -rkey intermediate/private/ocsp.example.com.key.pem \
      -rsigner intermediate/certs/ocsp.example.com.cert.pem \
      -nrequest 1

Enter pass phrase for ocsp.example.com.key.pem: secretpassword
```

In another terminal, send a query to the OCSP responder. The `-cert` option specifies the certificate to query.

```
openssl ocsp -CAfile intermediate/certs/ca-chain.cert.pem -url http://127.0.0.1:2560 -resp_text \
      -issuer intermediate/certs/intermediate.cert.pem \
      -cert intermediate/certs/test.example.com.cert.pem
```

The start of the output shows:

* whether a successful response was received (`OCSP Response Status`)
* the identity of the responder (`Responder Id`)
* the revocation status of the certificate (`Cert Status`)

```
OCSP Response Data:
    OCSP Response Status: successful (0x0)
    Response Type: Basic OCSP Response
    Version: 1 (0x0)
    Responder Id: ... CN = ocsp.example.com
    Produced At: Apr 11 12:59:51 2015 GMT
    Responses:
    Certificate ID:
      Hash Algorithm: sha1
      Issuer Name Hash: E35979B6D0A973EBE8AEDED75D8C27D67D2A0334
      Issuer Key Hash: 69E8EC547F252360E5B6E77261F1D4B921D445E9
      Serial Number: 1003
    Cert Status: good
    This Update: Apr 11 12:59:51 2015 GMT
```

Revoke the certificate.

```
openssl ca -config intermediate/openssl.cnf -revoke intermediate/certs/test.example.com.cert.pem

Enter pass phrase for intermediate.key.pem: secretpassword
Revoking Certificate 1003.
Data Base Updated
```

As before, run the OCSP responder and on another terminal send a query. This time, the output shows `Cert Status: revoked` and a `Revocation Time`.

```
OCSP Response Data:
    OCSP Response Status: successful (0x0)
    Response Type: Basic OCSP Response
    Version: 1 (0x0)
    Responder Id: ... CN = ocsp.example.com
    Produced At: Apr 11 13:03:00 2015 GMT
    Responses:
    Certificate ID:
      Hash Algorithm: sha1
      Issuer Name Hash: E35979B6D0A973EBE8AEDED75D8C27D67D2A0334
      Issuer Key Hash: 69E8EC547F252360E5B6E77261F1D4B921D445E9
      Serial Number: 1003
    Cert Status: revoked
    Revocation Time: Apr 11 13:01:09 2015 GMT
    This Update: Apr 11 13:03:00 2015 GMT
```
</details>

## Ekler

### Kök CA yapılandırma dosyası

```
# OpenSSL root CA configuration file.
# Copy to `/root/ca/openssl.cnf`.

[ ca ]
# `man ca`
default_ca = CA_default

[ CA_default ]
# Directory and file locations.
dir               = /root/ca
certs             = $dir/certs
crl_dir           = $dir/crl
new_certs_dir     = $dir/newcerts
database          = $dir/index.txt
serial            = $dir/serial
RANDFILE          = $dir/private/.rand

# The root key and root certificate.
private_key       = $dir/private/ca.key.pem
certificate       = $dir/certs/ca.cert.pem

# For certificate revocation lists.
crlnumber         = $dir/crlnumber
crl               = $dir/crl/ca.crl.pem
crl_extensions    = crl_ext
default_crl_days  = 30

# SHA-1 is deprecated, so use SHA-2 instead.
default_md        = sha256

name_opt          = ca_default
cert_opt          = ca_default
default_days      = 375
preserve          = no
policy            = policy_strict

[ policy_strict ]
# The root CA should only sign intermediate certificates that match.
# See the POLICY FORMAT section of `man ca`.
countryName             = match
stateOrProvinceName     = match
organizationName        = match
organizationalUnitName  = optional
commonName              = supplied
emailAddress            = optional

[ policy_loose ]
# Allow the intermediate CA to sign a more diverse range of certificates.
# See the POLICY FORMAT section of the `ca` man page.
countryName             = optional
stateOrProvinceName     = optional
localityName            = optional
organizationName        = optional
organizationalUnitName  = optional
commonName              = supplied
emailAddress            = optional

[ req ]
# Options for the `req` tool (`man req`).
default_bits        = 2048
distinguished_name  = req_distinguished_name
string_mask         = utf8only

# SHA-1 is deprecated, so use SHA-2 instead.
default_md          = sha256

# Extension to add when the -x509 option is used.
x509_extensions     = v3_ca

[ req_distinguished_name ]
# See <https://en.wikipedia.org/wiki/Certificate_signing_request>.
countryName                     = Country Name (2 letter code)
stateOrProvinceName             = State or Province Name
localityName                    = Locality Name
0.organizationName              = Organization Name
organizationalUnitName          = Organizational Unit Name
commonName                      = Common Name
emailAddress                    = Email Address

# Optionally, specify some defaults.
countryName_default             = GB
stateOrProvinceName_default     = England
localityName_default            =
0.organizationName_default      = Alice Ltd
organizationalUnitName_default  =
emailAddress_default            =

[ v3_ca ]
# Extensions for a typical CA (`man x509v3_config`).
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always,issuer
basicConstraints = critical, CA:true
keyUsage = critical, digitalSignature, cRLSign, keyCertSign

[ v3_intermediate_ca ]
# Extensions for a typical intermediate CA (`man x509v3_config`).
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always,issuer
basicConstraints = critical, CA:true, pathlen:0
keyUsage = critical, digitalSignature, cRLSign, keyCertSign

[ usr_cert ]
# Extensions for client certificates (`man x509v3_config`).
basicConstraints = CA:FALSE
nsCertType = client, email
nsComment = "OpenSSL Generated Client Certificate"
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid,issuer
keyUsage = critical, nonRepudiation, digitalSignature, keyEncipherment
extendedKeyUsage = clientAuth, emailProtection

[ server_cert ]
# Extensions for server certificates (`man x509v3_config`).
basicConstraints = CA:FALSE
nsCertType = server
nsComment = "OpenSSL Generated Server Certificate"
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid,issuer:always
keyUsage = critical, digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth

[ crl_ext ]
# Extension for CRLs (`man x509v3_config`).
authorityKeyIdentifier=keyid:always

[ ocsp ]
# Extension for OCSP signing certificates (`man ocsp`).
basicConstraints = CA:FALSE
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid,issuer
keyUsage = critical, digitalSignature
extendedKeyUsage = critical, OCSPSigning
```

### Ara CA yapılandırma dosyası

```
# OpenSSL intermediate CA configuration file.
# Copy to `/root/ca/intermediate/openssl.cnf`.

[ ca ]
# `man ca`
default_ca = CA_default

[ CA_default ]
# Directory and file locations.
dir               = /root/ca/intermediate
certs             = $dir/certs
crl_dir           = $dir/crl
new_certs_dir     = $dir/newcerts
database          = $dir/index.txt
serial            = $dir/serial
RANDFILE          = $dir/private/.rand

# The root key and root certificate.
private_key       = $dir/private/intermediate.key.pem
certificate       = $dir/certs/intermediate.cert.pem

# For certificate revocation lists.
crlnumber         = $dir/crlnumber
crl               = $dir/crl/intermediate.crl.pem
crl_extensions    = crl_ext
default_crl_days  = 30

# SHA-1 is deprecated, so use SHA-2 instead.
default_md        = sha256

name_opt          = ca_default
cert_opt          = ca_default
default_days      = 375
preserve          = no
policy            = policy_loose

[ policy_strict ]
# The root CA should only sign intermediate certificates that match.
# See the POLICY FORMAT section of `man ca`.
countryName             = match
stateOrProvinceName     = match
organizationName        = match
organizationalUnitName  = optional
commonName              = supplied
emailAddress            = optional

[ policy_loose ]
# Allow the intermediate CA to sign a more diverse range of certificates.
# See the POLICY FORMAT section of the `ca` man page.
countryName             = optional
stateOrProvinceName     = optional
localityName            = optional
organizationName        = optional
organizationalUnitName  = optional
commonName              = supplied
emailAddress            = optional

[ req ]
# Options for the `req` tool (`man req`).
default_bits        = 2048
distinguished_name  = req_distinguished_name
string_mask         = utf8only

# SHA-1 is deprecated, so use SHA-2 instead.
default_md          = sha256

# Extension to add when the -x509 option is used.
x509_extensions     = v3_ca

[ req_distinguished_name ]
# See <https://en.wikipedia.org/wiki/Certificate_signing_request>.
countryName                     = Country Name (2 letter code)
stateOrProvinceName             = State or Province Name
localityName                    = Locality Name
0.organizationName              = Organization Name
organizationalUnitName          = Organizational Unit Name
commonName                      = Common Name
emailAddress                    = Email Address

# Optionally, specify some defaults.
countryName_default             = GB
stateOrProvinceName_default     = England
localityName_default            =
0.organizationName_default      = Alice Ltd
organizationalUnitName_default  =
emailAddress_default            =

[ v3_ca ]
# Extensions for a typical CA (`man x509v3_config`).
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always,issuer
basicConstraints = critical, CA:true
keyUsage = critical, digitalSignature, cRLSign, keyCertSign

[ v3_intermediate_ca ]
# Extensions for a typical intermediate CA (`man x509v3_config`).
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always,issuer
basicConstraints = critical, CA:true, pathlen:0
keyUsage = critical, digitalSignature, cRLSign, keyCertSign

[ usr_cert ]
# Extensions for client certificates (`man x509v3_config`).
basicConstraints = CA:FALSE
nsCertType = client, email
nsComment = "OpenSSL Generated Client Certificate"
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid,issuer
keyUsage = critical, nonRepudiation, digitalSignature, keyEncipherment
extendedKeyUsage = clientAuth, emailProtection

[ server_cert ]
# Extensions for server certificates (`man x509v3_config`).
basicConstraints = CA:FALSE
nsCertType = server
nsComment = "OpenSSL Generated Server Certificate"
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid,issuer:always
keyUsage = critical, digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth

[ crl_ext ]
# Extension for CRLs (`man x509v3_config`).
authorityKeyIdentifier=keyid:always

[ ocsp ]
# Extension for OCSP signing certificates (`man ocsp`).
basicConstraints = CA:FALSE
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid,issuer
keyUsage = critical, digitalSignature
extendedKeyUsage = critical, OCSPSigning
```

<details>
## Appendix

### Root CA configuration file

```
# OpenSSL root CA configuration file.
# Copy to `/root/ca/openssl.cnf`.

[ ca ]
# `man ca`
default_ca = CA_default

[ CA_default ]
# Directory and file locations.
dir               = /root/ca
certs             = $dir/certs
crl_dir           = $dir/crl
new_certs_dir     = $dir/newcerts
database          = $dir/index.txt
serial            = $dir/serial
RANDFILE          = $dir/private/.rand

# The root key and root certificate.
private_key       = $dir/private/ca.key.pem
certificate       = $dir/certs/ca.cert.pem

# For certificate revocation lists.
crlnumber         = $dir/crlnumber
crl               = $dir/crl/ca.crl.pem
crl_extensions    = crl_ext
default_crl_days  = 30

# SHA-1 is deprecated, so use SHA-2 instead.
default_md        = sha256

name_opt          = ca_default
cert_opt          = ca_default
default_days      = 375
preserve          = no
policy            = policy_strict

[ policy_strict ]
# The root CA should only sign intermediate certificates that match.
# See the POLICY FORMAT section of `man ca`.
countryName             = match
stateOrProvinceName     = match
organizationName        = match
organizationalUnitName  = optional
commonName              = supplied
emailAddress            = optional

[ policy_loose ]
# Allow the intermediate CA to sign a more diverse range of certificates.
# See the POLICY FORMAT section of the `ca` man page.
countryName             = optional
stateOrProvinceName     = optional
localityName            = optional
organizationName        = optional
organizationalUnitName  = optional
commonName              = supplied
emailAddress            = optional

[ req ]
# Options for the `req` tool (`man req`).
default_bits        = 2048
distinguished_name  = req_distinguished_name
string_mask         = utf8only

# SHA-1 is deprecated, so use SHA-2 instead.
default_md          = sha256

# Extension to add when the -x509 option is used.
x509_extensions     = v3_ca

[ req_distinguished_name ]
# See <https://en.wikipedia.org/wiki/Certificate_signing_request>.
countryName                     = Country Name (2 letter code)
stateOrProvinceName             = State or Province Name
localityName                    = Locality Name
0.organizationName              = Organization Name
organizationalUnitName          = Organizational Unit Name
commonName                      = Common Name
emailAddress                    = Email Address

# Optionally, specify some defaults.
countryName_default             = GB
stateOrProvinceName_default     = England
localityName_default            =
0.organizationName_default      = Alice Ltd
organizationalUnitName_default  =
emailAddress_default            =

[ v3_ca ]
# Extensions for a typical CA (`man x509v3_config`).
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always,issuer
basicConstraints = critical, CA:true
keyUsage = critical, digitalSignature, cRLSign, keyCertSign

[ v3_intermediate_ca ]
# Extensions for a typical intermediate CA (`man x509v3_config`).
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always,issuer
basicConstraints = critical, CA:true, pathlen:0
keyUsage = critical, digitalSignature, cRLSign, keyCertSign

[ usr_cert ]
# Extensions for client certificates (`man x509v3_config`).
basicConstraints = CA:FALSE
nsCertType = client, email
nsComment = "OpenSSL Generated Client Certificate"
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid,issuer
keyUsage = critical, nonRepudiation, digitalSignature, keyEncipherment
extendedKeyUsage = clientAuth, emailProtection

[ server_cert ]
# Extensions for server certificates (`man x509v3_config`).
basicConstraints = CA:FALSE
nsCertType = server
nsComment = "OpenSSL Generated Server Certificate"
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid,issuer:always
keyUsage = critical, digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth

[ crl_ext ]
# Extension for CRLs (`man x509v3_config`).
authorityKeyIdentifier=keyid:always

[ ocsp ]
# Extension for OCSP signing certificates (`man ocsp`).
basicConstraints = CA:FALSE
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid,issuer
keyUsage = critical, digitalSignature
extendedKeyUsage = critical, OCSPSigning
```

### Intermediate CA configuration file

```
# OpenSSL intermediate CA configuration file.
# Copy to `/root/ca/intermediate/openssl.cnf`.

[ ca ]
# `man ca`
default_ca = CA_default

[ CA_default ]
# Directory and file locations.
dir               = /root/ca/intermediate
certs             = $dir/certs
crl_dir           = $dir/crl
new_certs_dir     = $dir/newcerts
database          = $dir/index.txt
serial            = $dir/serial
RANDFILE          = $dir/private/.rand

# The root key and root certificate.
private_key       = $dir/private/intermediate.key.pem
certificate       = $dir/certs/intermediate.cert.pem

# For certificate revocation lists.
crlnumber         = $dir/crlnumber
crl               = $dir/crl/intermediate.crl.pem
crl_extensions    = crl_ext
default_crl_days  = 30

# SHA-1 is deprecated, so use SHA-2 instead.
default_md        = sha256

name_opt          = ca_default
cert_opt          = ca_default
default_days      = 375
preserve          = no
policy            = policy_loose

[ policy_strict ]
# The root CA should only sign intermediate certificates that match.
# See the POLICY FORMAT section of `man ca`.
countryName             = match
stateOrProvinceName     = match
organizationName        = match
organizationalUnitName  = optional
commonName              = supplied
emailAddress            = optional

[ policy_loose ]
# Allow the intermediate CA to sign a more diverse range of certificates.
# See the POLICY FORMAT section of the `ca` man page.
countryName             = optional
stateOrProvinceName     = optional
localityName            = optional
organizationName        = optional
organizationalUnitName  = optional
commonName              = supplied
emailAddress            = optional

[ req ]
# Options for the `req` tool (`man req`).
default_bits        = 2048
distinguished_name  = req_distinguished_name
string_mask         = utf8only

# SHA-1 is deprecated, so use SHA-2 instead.
default_md          = sha256

# Extension to add when the -x509 option is used.
x509_extensions     = v3_ca

[ req_distinguished_name ]
# See <https://en.wikipedia.org/wiki/Certificate_signing_request>.
countryName                     = Country Name (2 letter code)
stateOrProvinceName             = State or Province Name
localityName                    = Locality Name
0.organizationName              = Organization Name
organizationalUnitName          = Organizational Unit Name
commonName                      = Common Name
emailAddress                    = Email Address

# Optionally, specify some defaults.
countryName_default             = GB
stateOrProvinceName_default     = England
localityName_default            =
0.organizationName_default      = Alice Ltd
organizationalUnitName_default  =
emailAddress_default            =

[ v3_ca ]
# Extensions for a typical CA (`man x509v3_config`).
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always,issuer
basicConstraints = critical, CA:true
keyUsage = critical, digitalSignature, cRLSign, keyCertSign

[ v3_intermediate_ca ]
# Extensions for a typical intermediate CA (`man x509v3_config`).
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always,issuer
basicConstraints = critical, CA:true, pathlen:0
keyUsage = critical, digitalSignature, cRLSign, keyCertSign

[ usr_cert ]
# Extensions for client certificates (`man x509v3_config`).
basicConstraints = CA:FALSE
nsCertType = client, email
nsComment = "OpenSSL Generated Client Certificate"
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid,issuer
keyUsage = critical, nonRepudiation, digitalSignature, keyEncipherment
extendedKeyUsage = clientAuth, emailProtection

[ server_cert ]
# Extensions for server certificates (`man x509v3_config`).
basicConstraints = CA:FALSE
nsCertType = server
nsComment = "OpenSSL Generated Server Certificate"
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid,issuer:always
keyUsage = critical, digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth

[ crl_ext ]
# Extension for CRLs (`man x509v3_config`).
authorityKeyIdentifier=keyid:always

[ ocsp ]
# Extension for OCSP signing certificates (`man ocsp`).
basicConstraints = CA:FALSE
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid,issuer
keyUsage = critical, digitalSignature
extendedKeyUsage = critical, OCSPSigning
```
</details>
