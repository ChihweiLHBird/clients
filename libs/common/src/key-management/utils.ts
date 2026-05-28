import { firstValueFrom, map, Observable } from "rxjs";

import { PasswordManagerClient } from "@bitwarden/sdk-internal";
import { UserId } from "@bitwarden/user-core";

import { SdkService } from "../platform/abstractions/sdk/sdk.service";

export async function firstValueFromOrThrow<T>(
  value: Observable<T | null>,
  name: string,
): Promise<T> {
  const result = await firstValueFrom(value);
  if (result == null) {
    throw new Error(`Failed to get ${name}`);
  }
  return result;
}

/**
 * A helper function to run code on a PasswordManagerClient. This will get the
 * locked or unlocked PasswordManagerClient depending on whether the user is currently locked or not.
 * This should be (later) handled within the SDK service instead.
 *
 * @param passedInFunction - A function is passed in. The function takes a password manager client and returns a result. The function is run as part of running withPasswordManagerSdk
 *   in order to uphold the lifetime rules of the SDK client.
 */
export async function withPasswordManagerSdk<TResult>(
  userId: UserId,
  sdkService: SdkService,
  passedInFunction: (sdk: PasswordManagerClient) => Promise<TResult>,
): Promise<TResult> {
  return await firstValueFrom(
    sdkService.userClient$(userId).pipe(
      map(async (sdk) => {
        if (sdk == null) {
          throw new Error("SDK not available");
        }

        using ref = sdk.take();
        return await passedInFunction(ref.value);
      }),
    ),
  );
}
