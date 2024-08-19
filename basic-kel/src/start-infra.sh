#!/bin/bash
#UID=$(id -u)


pkill -f "witness|watcher" -u $UID -e
rm ./db -rf
../target_from_keriox/debug/witness -c ../config/CH_wit_01_dev.yml &
../target_from_keriox/debug/witness -c ../config/CH_wit_02_dev.yml &
../target_from_keriox/debug/witness -c ../config/CH_wit_03_dev.yml &
../target_from_keriox/debug/witness -c ../config/CH_wit_04_dev.yml &
../target_from_keriox/debug/witness -c ../config/CH_wit_05_dev.yml &
../target_from_keriox/debug/witness -c ../config/CH_wit_06_dev.yml &
sleep 3
../target_from_keriox/debug/watcher -c ../config/CH_wat_01_dev.yml &
../target_from_keriox/debug/watcher -c ../config/CH_wat_02_dev.yml &
../target_from_keriox/debug/watcher -c ../config/CH_wat_03_dev.yml &
../target_from_keriox/debug/watcher -c ../config/CH_wat_04_dev.yml &
../target_from_keriox/debug/watcher -c ../config/CH_wat_05_dev.yml &
../target_from_keriox/debug/watcher -c ../config/CH_wat_06_dev.yml &
echo "DEMO INFRA STARTED" &
wait
