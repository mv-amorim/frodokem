Implementação do FrodoKEM para o microcontrolador ESP32-S3 usando processamento dual core.

Para alterar as configurações, basta acessar o *SDK Configuration Editor (menuconfig)* do ESP-IDF e ir até a seção *FrodoKEM Configuration*. Lá é possível alterar o algoritmo FrodoKEM usado (-640, -976 ou -1344), habilitar AES na geração da matriz A e desativar o dual core.

ESP-IDF v5.1.4