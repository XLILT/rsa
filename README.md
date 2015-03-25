# rsa
rsa algorihtm with library openssl

Brief Introduction 

This is a RSA encryption/decryption algorithm demo using openssl library. 

Build relay on:

openssl : yum install -y openssl-devel openssl

scons : yum install -y scons

build all: scons

run:

step1: generate private key file
     
    openssl genrsa -out test.key 1024

step2: generate public key file

   openssl rsa -in test.key -pubout -out test_pub.key

step3: run demo

    ./rsa
