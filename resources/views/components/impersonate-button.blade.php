{{--
    A POST form, not a link: entering an account changes state, so it must not be a
    GET that a crawler, a prefetcher or a pasted URL can trigger.

    Deliberately unstyled. The attribute bag is forwarded to the submit control so a
    host application's own button classes apply without publishing this view.
--}}
<form method="POST" action="{{ $action }}" class="impersonator-form" data-impersonator-form>
    @csrf

    <input type="hidden" name="target_type" value="{{ $targetType }}">
    <input type="hidden" name="target_id" value="{{ $targetId }}">

    @if ($mode)
        <input type="hidden" name="mode" value="{{ $mode }}">
    @endif

    @if ($redirectTo)
        <input type="hidden" name="redirect_to" value="{{ $redirectTo }}">
    @endif

    @if ($reason)
        <input type="hidden" name="reason" value="{{ $reason }}">
    @elseif ($reasonRequired)
        {{-- The server refuses a missing reason, so prompt for one here rather than
             letting the operator discover the requirement via a 403. --}}
        <label class="impersonator-form__reason">
            <span>Reason</span>
            <input type="text" name="reason" required maxlength="500"
                   placeholder="e.g. Ticket #4182">
        </label>
    @endif

    <button type="submit"
            {{ $attributes->merge(['class' => 'impersonator-form__submit']) }}
            @if ($confirm)
                onclick="return confirm({{ Js::from('Impersonate ' . ($displayName ?? 'this user') . '?') }})"
            @endif
    >{{ $label }}</button>
</form>
