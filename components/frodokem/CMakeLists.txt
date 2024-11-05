idf_component_register(SRCS "util.c" "frodokem.c" "sha3/fips202.c" "aes/aes.c"
                    INCLUDE_DIRS "." "sha3" "aes"
                    REQUIRES "esp_hw_support" "bootloader_support" "mbedtls")

if(CONFIG_USE_FRODO1344)
    add_compile_definitions(USE_FRODO1344)
elseif(CONFIG_USE_FRODO976)
    add_compile_definitions(USE_FRODO976)
else()
    add_compile_definitions(USE_FRODO640)
endif()

if(CONFIG_FRODOKEM_USE_AES)
    add_compile_definitions(USE_AES)
endif()

if(CONFIG_FRODOKEM_USE_SINGLECORE)
    add_compile_definitions(USE_SINGLECORE)
endif()