CONFIG_TEST_PUBRSA=m
CONFIG_TEST_PRIRSA=m
CONFIG_TEST_BASE64=m

obj-$(CONFIG_TEST_PUBRSA) += test_pubrsa.o
test_pubrsa-objs:= pub_rsa.o rsa_test.o


obj-$(CONFIG_TEST_PRIRSA) += test_prirsa.o
test_prirsa-objs:= pri_rsa.o rsa_test.o

obj-$(CONFIG_TEST_BASE64) += test_base64.o
test_base64-objs:= base64_test.o rsa_test.o
