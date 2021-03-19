
requirements=(
python3
iptables
crontab
)

ROOT_ID=0

[[ $(id -u) -eq ${ROOT_ID} ]] || { echo "must run as root user!" && exit 1; }

DIR="$(realpath $(dirname $0))"
cd $DIR


which python3 >/dev/null 2>&1 || { echo "please install python3 at first!" && exit 1; }

python3 -c 'import pip' 2>/dev/null || { echo "please install python3-pip at first!" && exit 1; }

for p in ${requirements[@]}; do
    type $p 2>/dev/null || { echo "please install $p at first!" && exit 1; }
done

python3 -m pip install -r requirements.txt

source install.rclocal.sh
source install.crontab.sh
