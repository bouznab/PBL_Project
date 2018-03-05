#!/bin/bash
python scripts/iperf_data_parser.py $1 $2 $3
Rscript scripts/iperfgraphs.R
