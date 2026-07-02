/*
 * Copyright (c) 2023-2026 European Commission
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package eu.europa.ec.eudi.pidissuer.adapter.out.util

import arrow.core.Either
import arrow.core.getOrElse
import arrow.core.raise.catch
import arrow.core.raise.context.Raise
import arrow.core.raise.context.either
import arrow.core.raise.context.raise

context(_: Raise<Throwable>)
inline fun <T> catchAndRethrow(block: () -> T): T =
    catch({ block() }) { raise(it) }


context(_: Raise<E>)
inline fun <E, T> eitherOrRaise(eff: context(Raise<Throwable>)() -> T, transform: (Throwable) -> E): T =
    either { eff() }
    .getOrElse { error ->
        raise(transform(error))
    }

inline fun <E, T, R> handleAppError(block: context(Raise<E>)() -> T, left: (E) -> R, right: (T) -> R): R =
    either { block() }.fold(left, right)

typealias RaiseContext<E, R> = context(Raise<E>)() -> R

inline fun <E, R> toEither(eff: RaiseContext<E, R>): Either<E, R> = either { eff() }
