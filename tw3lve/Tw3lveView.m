//
//  ViewController.m
//  tw3lve
//
//  Created by Tanay Findley on 4/7/19.
//  Copyright © 2019 Tanay Findley. All rights reserved.
//

#import "Tw3lveView.h"
#include "KernelMemory.h"
#include "OffsetHolder.h"
#include "KernelUtils.h"
#include "ms_offsets.h"
#include "machswap.h"
#include "VarHolder.h"
#include "patchfinder64.h"
#include "utils.h"

#include "voucher_swap.h"
#include "kernel_slide.h"
#include "kernel_memory.h"
#include "PFOffs.h"
#include "offsets.h"

#include "remap_tfp_set_hsp.h"

#include "kernel_exec.h"

#define KERNEL_SEARCH_ADDRESS 0xfffffff007004000

@interface Tw3lveView ()
{
    
    IBOutlet UILabel *DeviceString;
    IBOutlet UIButton *leButton;
}

@property (strong, nonatomic) IBOutlet UITextView *uiLog;


@end

@implementation Tw3lveView



Tw3lveView *sharedController = nil;

- (void)viewDidLoad {
    [super viewDidLoad];
    sharedController = self;
    DeviceString.text = [UIDevice currentDevice].name;
}

+ (Tw3lveView *)sharedController {
    return sharedController;
}

/***
 Thanks Conor
 **/
void runOnMainQueueWithoutDeadlocking(void (^block)(void))
{
    if ([NSThread isMainThread])
    {
        block();
    }
    else
    {
        dispatch_sync(dispatch_get_main_queue(), block);
    }
}





/***********
 
    MAGIC
 
 ***********/

bool restoreFS = false;

bool voucher_swap_exp = false;

void jelbrek()
{
    while (true)
    {
        //Init Offsets
        runOnMainQueueWithoutDeadlocking(^{
            logToUI(@"\n[*] Getting Offsets...");
        });
        offs_init();

        NSLog(@"Jailbreak Thread Started!");
        
        host_t host = mach_host_self();
        
        
        //Init Exploit
        if (voucher_swap_exp)
        {
            runOnMainQueueWithoutDeadlocking(^{
                logToUI(@"\n[*] Running Voucher Swap...");
            });
            
            voucher_swap();
            set_tfp0_rw(kernel_task_port);
            
            
            if (MACH_PORT_VALID(tfp0)) {
                
                kbase = find_kernel_base();
                kernel_slide = (kbase - KERNEL_SEARCH_ADDRESS);
                
                runOnMainQueueWithoutDeadlocking(^{
                    logToUI(@"\n[*] Getting Root...");
                });
                rootMe(0, selfproc());
                runOnMainQueueWithoutDeadlocking(^{
                    logToUI(@"\n[*] Unsandboxing...");
                });
                unsandbox(selfproc());
                
            } else {
                LOGME("ERROR!");
                break;
            }
            
            
            
        } else {
            runOnMainQueueWithoutDeadlocking(^{
                logToUI(@"\n[*] Running Machswap...");
            });
            ms_offsets_t *ms_offs = get_machswap_offsets();
            machswap_exploit(ms_offs, &tfp0, &kbase);
            
            if (MACH_PORT_VALID(tfp0))
            {
                kernel_slide = (kbase - KERNEL_SEARCH_ADDRESS);
                //Machswap and Machswap2 already gave us undandboxing and root. Thanks! <3
                runOnMainQueueWithoutDeadlocking(^{
                    logToUI(@"\n[*] We already have root and unsandbox.");
                });
            } else {
                LOGME("ERROR!");
                break;
            }
            
        }
        

        //Log
        NSLog(@"%@", [NSString stringWithFormat:@"TFP0: 0x%x", tfp0]);
        NSLog(@"%@", [NSString stringWithFormat:@"KERNEL BASE: %llx", kbase]);
        NSLog(@"%@", [NSString stringWithFormat:@"KERNEL SLIDE: %llx", kernel_slide]);
        
        NSLog(@"UID: %u", getuid());
        NSLog(@"GID: %u", getgid());
        
        
        //PF64 (STAGE 1)
        runOnMainQueueWithoutDeadlocking(^{
            logToUI(@"\n[*] Init Patchfinder64...");
        });
        initPF64();
        
        //GET (4...) OFFSETS (STAGE 2)
        runOnMainQueueWithoutDeadlocking(^{
            logToUI(@"\n[*] Getting Offsets (2)...");
        });
        getOffsets();
        
        //REMAP AND UNEXPORT (STAGE 3)
        runOnMainQueueWithoutDeadlocking(^{
            logToUI(@"\n[*] Remapping TFP0...");
        });
        setHSP4();
        
        runOnMainQueueWithoutDeadlocking(^{
            logToUI(@"\n[*] Unexporting TFP0...");
        });
        ux_tfp0(host, 0x80000000 | 3);
        
        
        //INIT KEXECUTE (STAGE 4)
        runOnMainQueueWithoutDeadlocking(^{
            logToUI(@"\n[*] Init kexecute...");
        });
        init_kexecute();
        
        //REMOUNT (STAGE 5)
        runOnMainQueueWithoutDeadlocking(^{
            logToUI(@"\n[*] Remounting RootFS...");
        });
        remountFS();
        
        
        //IS UNC0VER INSTALLED?
        is_unc0ver_installed();
        
        
        
        if (restoreFS == true)
        {
            runOnMainQueueWithoutDeadlocking(^{
                logToUI(@"\n[DANGER] Restoring RootFS...");
            });
            restoreRootFS();
        }
        
        //BOOTSTRAP (STAGE 6)
        runOnMainQueueWithoutDeadlocking(^{
            logToUI(@"\n[*] Extracting Bootstrap...");
        });
        extractBootstrap();
        
        
        
        break;
        
    }
}

- (IBAction)resetOwO:(id)sender {
   
    
    restoreFS = true;
}


void logToUI(NSString *text)
{
    runOnMainQueueWithoutDeadlocking(^{
        NSLog(@"%@", text);
        Tw3lveView.sharedController.uiLog.text = [Tw3lveView.sharedController.uiLog.text stringByAppendingString:text];
        NSRange range = NSMakeRange(Tw3lveView.sharedController.uiLog.text.length - 1, 1);
        [Tw3lveView.sharedController.uiLog scrollRangeToVisible:range];
    });
}



- (IBAction)jelbrekClik:(id)sender {
    
     [sender setTitle:@"Jailbreaking..." forState:UIControlStateNormal];
     [sender setEnabled:false];
    
   
    runOnMainQueueWithoutDeadlocking(^{
        logToUI(@"\n[*] Staring Jailbreak Thread...");
    });
    
    
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_HIGH, 0ul), ^{
        jelbrek();
    });
}


@end
