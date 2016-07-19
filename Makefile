CONFIG_TEST_RSA=m


obj-$(CONFIG_TEST_RSA) += test_rsa.o
test_rsa-objs:= rsa.o rsa_test.o
