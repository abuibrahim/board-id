ifneq ($(KERNELRELEASE),)
obj-m += board-id.o
else
all:
	$(MAKE) -C $(KERNEL_SRC) M=$$PWD modules

modules_install:
	$(MAKE) -C $(KERNEL_SRC) M=$$PWD modules_install

clean:
	$(MAKE) -C $(KERNEL_SRC) M=$$PWD clean
endif
