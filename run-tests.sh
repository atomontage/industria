#!/bin/sh

FAILURES=""
SUCCESSES=""
export DISABLE_SLOW_TESTS=yes

run_test()
{
    printf "\033[33;1mRunning %s...\033[0m\n" "$1"
    if ! scheme-script "$1"; then
        FAILURES=$(printf "%s\n  \033[31;1m%s\033[0m" "$FAILURES" "$1")
    else
        SUCCESSES="$SUCCESSES
  $1"
    fi
}

for fn in tests/*.sps; do
    case $fn in
        *.*.sps)
            ;;
        *.sps)
            run_test "$fn"
            ;;
    esac
done

cat <<EOF
These test suites ran successfully:
$SUCCESSES

These test suites exited with a failure code:
$FAILURES

EOF

if [ x"$FAILURES" != x"" ]; then
    exit 1
fi

exit 0
