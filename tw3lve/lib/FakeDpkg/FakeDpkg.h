//
//  FakeDpkg.h
//  tw3lve
//
//  Created by Tanay Findley on 4/10/19.
//  Copyright © 2019 Tanay Findley. All rights reserved.
//

#ifndef FakeDpkg_h
#define FakeDpkg_h

int versioncomp(NSString *v1, NSString *v2);
NSDictionary *parseDependsOrProvides(NSString *string);
BOOL compareDpkgVersion(NSString *version1, NSString *op, NSString *version2, BOOL *result);
NSString *versionOfPkg(NSString *pkg);
NSArray *resolveDepsForPkg(NSString * _Nonnull pkg, BOOL noPreDeps);
BOOL extractDebsForPkg(NSString *pkg, NSMutableArray *installed, BOOL preDeps);
NSDictionary *getPkgs(void);
NSString *debForPkg(NSString *pkg);
NSArray <NSString*> *debsForPkgs(NSArray <NSString*> *pkgs);

#endif /* FakeDpkg_h */
