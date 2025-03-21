/* ****************************************************************
 *
 * Copyright 2024 Samsung Electronics All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 ******************************************************************/

#ifndef _FOCUS_MANAGERWORKER_H
#define _FOCUS_MANAGERWORKER_H

#include <memory>
#include <media/FocusManager.h>
#include "MediaWorker.h"

namespace media {
class FocusManagerWorker : public MediaWorker
{
public:
	static FocusManagerWorker &getWorker();
private:
	FocusManagerWorker();

};
} // namespace media
#endif
