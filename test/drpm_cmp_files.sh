#!/usr/bin/env bash

script=$0

function usage {
    echo "usage: ${script} [ -d <prefix> ] [ -s ] [ -l ]"
}

prefix=""
skip=false
lzip=false

while getopts "hd:sl" opt; do
    case $opt in
        h)
            usage
            exit 0
            ;;
        d)
            prefix="${OPTARG%/}/"
            ;;
        s)
            skip=true
            ;;
        l)
            lzip=true
            ;;
        *)
            usage
            exit 1
            ;;
    esac
done
shift $((OPTIND-1))

pack1=drpm
pack2=cmocka

oldrpm1="${prefix}${pack1}-old.rpm"
newrpm1="${prefix}${pack1}-new.rpm"
oldrpm2="${prefix}${pack2}-old.rpm"
newrpm2="${prefix}${pack2}-new.rpm"

tmpdelta="${prefix}tmp.drpm"

copyseq="${prefix}refseqfile-copy.txt"
refseq="${prefix}refseqfile.txt"
cmpseq="${prefix}seqfile.txt"

copyDRPMsha256="${prefix}refdrpm-copy.sha256"
refDRPMsha256="${prefix}refdrpm.sha256"
cmpDRPMsha256="${prefix}drpm.sha256"

refRPMsha256="${prefix}refrpm.sha256"
cmpRPMsha256="${prefix}rpm.sha256"

declare -a deltas=("${prefix}nodiff.drpm" \
                   "${prefix}identity.drpm" \
                   "${prefix}rpmonly.drpm" \
                   "${prefix}standard.drpm" \
                   "${prefix}rpmonly-noaddblk.drpm")

if [ $lzip = true ]; then
    deltas+=("${prefix}standard-lzip.drpm")
fi

rpmstandard="${prefix}standard.rpm"
rpmrpmonly="${prefix}rpmonly-noaddblk.rpm"
rpmlzip="${prefix}standard-lzip.rpm"

if ! [ -f $oldrpm1 ] || ! [ -f $newrpm1 ] || ! [ -f $oldrpm2 ] || ! [ -f $newrpm2 ]; then
    echo "setup error: missing RPM files"
    exit 1
fi

if ! [ -f $copyseq ] || ! [ -f $copyDRPMsha256 ]; then
    echo "setup error: missing backup copies of makedeltarpm output"
    exit 1
fi

for delta in ${deltas[@]}; do
    if ! [ -f ${delta} ]; then
        echo "previous error: missing deltarpm: ${delta}"
        exit 1
    fi
done

if ! [ -f ${cmpseq} ]; then
    echo "previous error: missing sequence file"
    exit 1
fi

if ! [ -f ${rpmstandard} ] || ! [ -f ${rpmrpmonly} ]; then
    echo "previous error: missing RPM files"
    exit 1
fi

if [ $lzip = true ] && ! [ -f ${rpmlzip} ]; then
    echo "previous error: missing RPM files (lzip)"
    exit 1
fi

rm -f ${refDRPMsha256} ${cmpDRPMsha256} ${refRPMsha256} ${cmpRPMsha256}

if [ $skip = true ]; then
    cp ${copyDRPMsha256} ${refDRPMsha256}
    cp ${copyseq} ${refseq}
else
    declare -a makeargs=("-u -r ${oldrpm1}" \
                         "-u -V 2 -z uncompressed ${newrpm1}" \
                         "-r -z bzip2.7,lzma ${oldrpm2} ${newrpm2}" \
                         "-s ${refseq} ${oldrpm1} ${newrpm1}" \
                         "-r -z gzip,off ${oldrpm2} ${newrpm2}")
    oldIFS=${IFS}
    IFS=""
    for args in ${makeargs[@]}; do
        command="makedeltarpm ${args} ${tmpdelta}"
        eval ${command}
        if ! [ $? ]; then
            echo "failed with command '${command}'"
            exit 1
        fi
        sha256sum ${tmpdelta} | awk '{ print $1 }' >> ${refDRPMsha256}
    done
    IFS=${oldIFS}
fi

for delta in ${deltas[@]}; do
    sha256sum ${delta} | awk '{ print $1 }' >> ${cmpDRPMsha256}
done

sha256sum ${newrpm1} | awk '{ print $1 }' >> ${refRPMsha256}
sha256sum ${newrpm2} | awk '{ print $1 }' >> ${refRPMsha256}

sha256sum ${rpmstandard} | awk '{ print $1 }' >> ${cmpRPMsha256}
sha256sum ${rpmrpmonly} | awk '{ print $1 }' >> ${cmpRPMsha256}

if [ $lzip = true ]; then
    sha256sum ${newrpm2} | awk '{ print $1 }' >> ${refRPMsha256}
    sha256sum ${rpmlzip} | awk '{ print $1 }' >> ${cmpRPMsha256}
fi

ret=0

diff ${refDRPMsha256} ${cmpDRPMsha256}
if ! [ $? ]; then
    ret=$?
fi

diff ${refseq} ${cmpseq}
if [ $ret ] && ! [ $? ]; then
    ret=$?
fi

diff ${refRPMsha256} ${cmpRPMsha256}
if [ $ret ] && ! [ $? ]; then
    ret=$?
fi

rm -f ${refDRPMsha256} ${cmpDRPMsha256} ${refRPMsha256} ${cmpRPMsha256} \
      ${refseq} ${cmpseq} ${deltas[*]} ${deltatmp}

exit $ret

