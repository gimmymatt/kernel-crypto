CONFIG_TEST_PUBRSA=m
CONFIG_TEST_PRIRSA=m


obj-$(CONFIG_TEST_PUBRSA) += test_pubrsa.o
test_pubrsa-objs:= pub_rsa.o rsa_test.o


obj-$(CONFIG_TEST_PRIRSA) += test_prirsa.o
test_prirsa-objs:= pri_rsa.o rsa_test.o
