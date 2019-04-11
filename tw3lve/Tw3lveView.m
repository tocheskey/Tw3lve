//
//  ViewController.m
//  tw3lve
//
//  Created by Tanay Findley on 4/7/19.
//  Copyright © 2019 Tanay Findley. All rights reserved.
//

#import "Tw3lveView.h"

#include "OffsetHolder.h"

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
    IBOutlet UIButton *leButton;
}

@property (strong, nonatomic) IBOutlet UITextView *uiLog;


@end

@implementation Tw3lveView



Tw3lveView *sharedController = nil;

- (void)viewDidLoad {
    [super viewDidLoad];
    sharedController = self;
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
        offs_init();

        NSLog(@"Jailbreak Thread Started!");
        
        
        //Init Exploit
        if (voucher_swap_exp)
        {
            voucher_swap();
            tfp0 = kernel_task_port;
            kernel_slide_init();
            kbase = (kernel_slide + KERNEL_SEARCH_ADDRESS);
            
            //GET ROOT
            rootMe(0, selfproc());
            unsandbox(selfproc());
            
            
        } else {
            ms_offsets_t *ms_offs = get_machswap_offsets();
            machswap_exploit(ms_offs, &tfp0, &kbase);
            kernel_slide = (kbase - KERNEL_SEARCH_ADDRESS);
            //Machswap and Machswap2 already gave us undandboxing and root. Thanks! <3
            
        }
        

        //Log
        NSLog(@"%@", [NSString stringWithFormat:@"TFP0: %x", tfp0]);
        NSLog(@"%@", [NSString stringWithFormat:@"KERNEL BASE: %llx", kbase]);
        NSLog(@"%@", [NSString stringWithFormat:@"KERNEL SLIDE: %llx", kernel_slide]);
        
        NSLog(@"UID: %u", getuid());
        NSLog(@"GID: %u", getgid());
        
        
        //Remap TFP0 (STAGE 1)
        initPF64();
        
        //GET (4...) OFFSETS (STAGE 2)
        getOffsets();
        
        //REMAP (STAGE 3)
        remap_tfp0_set_hsp4(&tfp0);
        
        //INIT KEXECUTE (STAGE 4)
        LOGME("Init kernel_exection");
        init_kexecute();
        
        
        //REMOUNT (STAGE 5)
        LOGME("Remount Time!");
        remountFS();
        
        if (restoreFS == true)
        {
            LOGME("[DANGER] Restoring RootFS...");
            restoreRootFS();
        }
        
        extractBootstrap();
        
        
        
        
        break;
        
    }
}

- (IBAction)resetOwO:(id)sender {
    [sender setTitle:@"Will Restore." forState:UIControlStateNormal];
    
    restoreFS = true;
}




- (IBAction)jelbrekClik:(id)sender {
    
    runOnMainQueueWithoutDeadlocking(^{
        NSLog(@"Jailbreak Button Clicked");
        Tw3lveView.sharedController.uiLog.text = [Tw3lveView.sharedController.uiLog.text stringByAppendingString:@"\nJailbreak Clicked!"];
    });
    
    
    
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_HIGH, 0ul), ^{
        jelbrek();
    });
}

- (IBAction)jelbrekA12Clik:(id)sender {
    
    voucher_swap_exp = true;
    
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_HIGH, 0ul), ^{
        jelbrek();
    });
    
    
   
    
    
}



@end
