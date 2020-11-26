UFSRVCMD_INPUT_FILE = "ufsrvcmd_lexer_data.h"
TARGET_DIR = ".."

default: ufsrvcmd

ufsrvcmd:
	echo "Generating lexer tree for ufsrvcmd using ${UFSRVCMD_INPUT_FILE}"
	@if [ -r ${UFSRVCMD_INPUT_FILE} ]; then \
		gcc minilex.c -o minilex; \
		mv ${UFSRVCMD_INPUT_FILE} ${UFSRVCMD_INPUT_FILE}.old;   \
		./minilex > ${UFSRVCMD_INPUT_FILE};  \
		if [ -r ${UFSRVCMD_INPUT_FILE} ]; then \
			cp ${UFSRVCMD_INPUT_FILE} ${TARGET_DIR}; \
		else \
			echo "Error generating lexer file..."; \
			exit; \
		fi      \
	else    \
		echo "Error: No input file was found (expected ${UFSRVCMD_INPUT_FILE})"; \
	fi
