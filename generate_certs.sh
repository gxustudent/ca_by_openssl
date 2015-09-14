#!/bin/bash

set -e
ca_setup() {
  cert_dir=$1
  ca=$2
  pre=$3

  if [ -z "$ca" ]; then
    echo "CA name must be provided."
    return
  fi

  # Create serial and database files.
  serial="$cert_dir/$ca-serial"
  # The PreCA shall share the CA's serial file.
  # However, it needs a separate database, since we want to be able to issue
  # a cert with the same serial twice (once by the PreCA, once by the CA).
  if [ "$pre" == "true" ]; then
    database="$cert_dir/$ca-pre-database"
    conf=$ca-pre
  else
    database="$cert_dir/$ca-database"
    conf=$ca
    echo "0000000000000001" > $serial
  fi

  > $database
  > $database.attr

  # Create a CA config file from the default configuration
  # by setting the appropriate serial and database files.
  sed -e "s,default_serial,$serial," -e "s,default_database,$database," \
    default_ca.conf > $cert_dir/$conf.conf
}

request_cert() {
  cert_dir=$1 # Output directory
  subject=$2 # Name of output certificate
  config=$3 # Config file with certificate info.
  plaintext_key=$4 # Should the generated key be encrypted?

  if [ "$plaintext_key" == "true" ]; then
    password_options="-nodes"
  else
    password_options="-passout pass:password1"
  fi

  openssl req -new -newkey rsa:1024 -keyout $cert_dir/$subject-key.pem \
    -out $cert_dir/$subject-cert.csr -config $config $password_options
}

issue_cert() {
  cert_dir=$1
  issuer=$2
  subject=$3
  extfile=$4
  extensions=$5
  selfsign=$6
  out=$7

  if [ $selfsign == "true" ]; then
    cert_args="-selfsign"
  else
    cert_args="-cert $cert_dir/$issuer-cert.pem"
  fi

  echo -e "y\ny\n" | \
    openssl ca -in $cert_dir/$subject-cert.csr $cert_args \
    -keyfile $cert_dir/$issuer-key.pem -config $cert_dir/$issuer.conf \
    -extfile $extfile -extensions $extensions -passin pass:password1 \
    -outdir $cert_dir -out $cert_dir/$out-cert.pem
}

make_ca_certs() {
  cert_dir=$1
  hash_dir=$2
  ca=$3
  my_openssl=$4

  if [ "$my_openssl" == "" ]; then
    my_openssl=openssl;
  fi

  # Setup root CA database and files
  ca_setup $cert_dir $ca false

  # Create a self-signed root certificate
  request_cert $cert_dir $ca ca-cert.conf
  issue_cert $cert_dir $ca $ca ca-cert.conf v3_ca true $ca

  # Put the root certificate in a trusted directory.
  # CT server will not understand the hash format for OpenSSL < 1.0.0
  echo "OpenSSL version is: "
  $my_openssl version
  hash=$($my_openssl x509 -in $cert_dir/$ca-cert.pem -hash -noout)
  cp $cert_dir/$ca-cert.pem $hash_dir/$hash.0

  # Create a CA precert signing request.
  #request_cert $cert_dir $ca-pre ca-precert.conf
  # Sign the CA precert.
  #issue_cert $cert_dir $ca $ca-pre ca-precert.conf ct_ext false $ca-pre
  #ca_setup $cert_dir $ca true
}

make_intermediate_ca_certs() {
  cert_dir=$1
  intermediate=$2
  ca=$3

  # Issue an intermediate CA certificate
  request_cert $cert_dir $intermediate intermediate-ca-cert.conf
  issue_cert $cert_dir $ca $intermediate ca-cert.conf v3_ca false $intermediate

  # Setup a database for the intermediate CA
  ca_setup $cert_dir $intermediate false

  echo "0000000000000003" >  $cert_dir/$intermediate-serial

  # Issue a precert signing cert
  #request_cert $cert_dir $intermediate-pre intermediate-ca-precert.conf
  #issue_cert $cert_dir $intermediate $intermediate-pre \
  #  intermediate-ca-precert.conf ct_ext false $intermediate-pre

  #ca_setup $cert_dir $intermediate true
}

make_embedded_cert() {
  local cert_dir=$1 # Where CA certificate lives and output certs go
  local server=$2 # Prefix of the new certificate filename
  local ca=$3 # Prefix of the CA certificate file.
  local log_server_url=$4 # Log URL
  local ca_is_intermediate=$5 # CA cert is intermediate one
  local use_pre_ca=$6 # Using precertificate signing cert.

  local modified_config=${cert_dir}/${server}_precert.conf
  cp precert.conf $modified_config

  # Generate a new, unencrypted private key and CSR
  request_cert $cert_dir $server $modified_config true

  # Sign the CSR to get a log request
  if [ $use_pre_ca == "true" ]; then
    issue_cert $cert_dir $ca-pre $server $modified_config pre false $server-pre
  else
  # Issue a precert, but since it's not real, do not update the database.
    cp $cert_dir/$ca-database $cert_dir/$ca-database.bak
    issue_cert $cert_dir $ca $server $modified_config pre false $server-pre
    mv $cert_dir/$ca-database.bak $cert_dir/$ca-database
  fi

  # Upload the precert bundle
  # If we're using a Precert Signing CA then we need to send it along
  if [ $use_pre_ca == "true" ]; then
    cat $cert_dir/$server-pre-cert.pem $cert_dir/$ca-pre-cert.pem > \
      $cert_dir/$server-precert-tmp.pem
  else
    cat $cert_dir/$server-pre-cert.pem > $cert_dir/$server-precert-tmp.pem
  fi

  # If the CA is an intermediate, then we need to include its certificate, too.
  if [ $ca_is_intermediate == "true" ]; then
    cat $cert_dir/$server-precert-tmp.pem $cert_dir/$ca-cert.pem > \
      $cert_dir/$server-precert-bundle.pem
  else
    cat $cert_dir/$server-precert-tmp.pem > \
      $cert_dir/$server-precert-bundle.pem
  fi

:<<COMMENT
  # upload  
  python ct-proxy-test.py $cert_dir/test-embedded-pre-cert.pem $cert_dir/$server-pre-cert.proof

  # Create a new extensions config with the embedded proof
  cp $modified_config $cert_dir/$server-extensions.conf 

  gdb --args /home/dev/work/google_ct/certificate-transparency-master/cpp/client/ct configure_proof \
    --extensions_config_out=$cert_dir/$server-extensions.conf \
    --sct_token=$cert_dir/$server-pre-cert.proof --logtostderr=true 
  # Sign the certificate
  # Store the current serial number
  mv $cert_dir/$ca-serial $cert_dir/$ca-serial.bak
  # Instead reuse the serial number from the precert
  openssl x509 -in $cert_dir/$server-pre-cert.pem -serial -noout | \
    sed 's/serial=//' > $cert_dir/$ca-serial

  issue_cert $cert_dir $ca $server $cert_dir/$server-extensions.conf embedded \
    false $server

  # Restore the serial number
  mv $cert_dir/$ca-serial.bak $cert_dir/$ca-serial
COMMENT
}

make_end_certs() {
  local cert_dir=$1 # Where CA certificate lives and output certs go
  local server=$2 # Prefix of the new certificate filename
  local ca=$3 # Prefix of the CA certificate file.
  local common_name=$4 # Optional commonName value for certificate

  local modified_config=${cert_dir}/${server}_endcert.conf

  if [ -z "$common_name" ]; then
    cp endcert.conf $modified_config
  else
    echo "Will set the following common name: $common_name"
    sed -e "/0.organizationName=Certificate/ a commonName=$common_name" endcert.conf > $modified_config
  fi
  #ca_setup $cert_dir $common_name false
  # Generate a new, unencrypted private key and CSR
  request_cert $cert_dir $server $modified_config false 

  # Sign the CSR to get a log request
  issue_cert $cert_dir $ca $server $modified_config endcert false $server-out
}

make_embbed_end_certs() {
  local cert_dir=$1 # Where CA certificate lives and output certs go
  local server=$2 # Prefix of the new certificate filename
  local ca=$3 # Prefix of the CA certificate file.

  local modified_config=${cert_dir}/${server}_precert.conf
  cp precert.conf $modified_config

  # Generate a new, unencrypted private key and CSR
  request_cert $cert_dir $server $modified_config false

  issue_cert $cert_dir $ca $server $modified_config pre false $server-pre
}

# Generate new certs dynamically and repeat the test for valid certs
mkdir -p tmp
# A directory for trusted certs in OpenSSL "hash format"
mkdir -p tmp/ca-hashes

make_ca_certs `pwd`/tmp `pwd`/tmp/ca-hashes ca

make_intermediate_ca_certs `pwd`/tmp intermediate ca

for((i=1;i<50;i++));
do
  name="test"${i}
  make_embbed_end_certs  `pwd`/tmp $name intermediate
done

comment(){
make_end_certs `pwd`/tmp test1 intermediate 
make_end_certs `pwd`/tmp test2 intermediate 
make_embedded_cert `pwd`/tmp test-embedded intermediate "" false false 
}
