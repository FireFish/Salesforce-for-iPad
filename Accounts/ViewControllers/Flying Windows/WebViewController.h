/* 
 * Copyright (c) 2011, salesforce.com, inc.
 * Author: Jonathan Hersh jhersh@salesforce.com
 * All rights reserved.
 * 
 * Redistribution and use in source and binary forms, with or without modification, are permitted provided 
 * that the following conditions are met:
 * 
 *    Redistributions of source code must retain the above copyright notice, this list of conditions and the 
 *    following disclaimer.
 *  
 *    Redistributions in binary form must reproduce the above copyright notice, this list of conditions and 
 *    the following disclaimer in the documentation and/or other materials provided with the distribution. 
 *    
 *    Neither the name of salesforce.com, inc. nor the names of its contributors may be used to endorse or 
 *    promote products derived from this software without specific prior written permission.
 *  
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED 
 * WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A 
 * PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR 
 * ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED 
 * TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) 
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING 
 * NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE 
 * POSSIBILITY OF SUCH DAMAGE.
 */
#import <UIKit/UIKit.h>
#import "zkSforce.h"
#import "FlyingWindowController.h"
#import <MessageUI/MessageUI.h>
#import <MessageUI/MFMailComposeViewController.h>
#import "ChatterPostController.h"

@interface WebViewController : FlyingWindowController <UIActionSheetDelegate, MFMailComposeViewControllerDelegate, UIWebViewDelegate, UIPopoverControllerDelegate, ChatterPostDelegate> {
    int webviewLoads;
}

typedef enum WebViewActionButtons {
    ButtonPostToChatter = 0,
    ButtonCopyLink,
    ButtonMailLink,
    ButtonOpenInSafari,
    ButtonTweet,
    ButtonNumButtons
} WebViewActionButton;

@property (nonatomic) BOOL isFullScreen;

@property (nonatomic, retain) UIBarButtonItem *actionButton;
@property (nonatomic, retain) UIWebView *webView;
@property (nonatomic, retain) UIActionSheet *myActionSheet;
@property (nonatomic, retain) UIPopoverController *chatterPop;
@property (nonatomic, retain) NSString *destURL;

- (BOOL) supportsButtonAtIndex:(WebViewActionButton)index;

- (id) initWithFrame:(CGRect)frame;
- (void) loadURL:(NSString *)url;
- (UIToolbar *) toolBarForSide:(BOOL)isLeftSide;
- (IBAction) toggleFullScreen;
- (void) resetNavToolbar;

- (BOOL) isFullScreen;

- (void) dismissPopover;

@end
