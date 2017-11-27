#!/bin/bash
export TEST_BIN_NAME=$1
echo "Building ${TEST_BIN_NAME}"
shift 1
export BUILD_COMMAND=$@
echo "Build command: ${BUILD_COMMAND}"
eval ${BUILD_COMMAND} #>/dev/null 2>/dev/null
if [ $? -eq 0 ]; then
	exit 1;
fi
echo "#!/bin/bash" > ${TEST_BIN_NAME}
chmod u+x ${TEST_BIN_NAME}
exit 0;

