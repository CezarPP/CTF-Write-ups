#!/bin/bash

nume='jibeqnocfjjuijypians'

for i in {1..1000}:
do
	mv $nume $nume.gz
	gunzip $nume.gz
	mv $nume $nume.zip
	unzip -P password $nume.zip
	cd archives/
	nume=$(ls)
	echo "$nume"
done
