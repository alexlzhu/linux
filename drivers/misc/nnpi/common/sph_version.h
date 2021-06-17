/*******************************************************************************
 * INTEL CORPORATION CONFIDENTIAL Copyright(c) 2017-2021 Intel Corporation. All Rights Reserved.
 *
 * The source code contained or described herein and all documents related to the
 * source code ("Material") are owned by Intel Corporation or its suppliers or
 * licensors. Title to the Material remains with Intel Corporation or its suppliers
 * and licensors. The Material contains trade secrets and proprietary and
 * confidential information of Intel or its suppliers and licensors. The Material
 * is protected by worldwide copyright and trade secret laws and treaty provisions.
 * No part of the Material may be used, copied, reproduced, modified, published,
 * uploaded, posted, transmitted, distributed, or disclosed in any way without
 * Intel's prior express written permission.
 *
 * No license under any patent, copyright, trade secret or other intellectual
 * property right is granted to or conferred upon you by disclosure or delivery of
 * the Materials, either expressly, by implication, inducement, estoppel or
 * otherwise. Any license under such intellectual property rights must be express
 * and approved by Intel in writing.
 ********************************************************************************/
#ifndef _NNP_VERSION_H
#define _NNP_VERSION_H

#define _STR(x) #x
#define STR(x) _STR(x)

#define SPH_MAJOR 0
#define SPH_MINOR 11
#define SPH_PATCH 0
#define SPH_PATCH_MINOR 0

#define NNP_VERSION  STR(VERSION: v.SPH_MAJOR.SPH_MINOR.SPH_PATCH.SPH_PATCH_MINOR)
#define AUTHOR_STR   STR(AUTHOR: Intel Corporation 2018-2021)
#define SPH_GIT_HASH STR(gh.GIT_HASH)

#ident NNP_VERSION
#ident AUTHOR_STR
#ident SPH_GIT_HASH
#endif
