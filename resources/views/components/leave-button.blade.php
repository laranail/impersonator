{{--
    Leaving is a de-escalation and is always permitted, so a plain link is fine here —
    there is no state an attacker gains by causing somebody to stop impersonating.
--}}
<a href="{{ $url }}" {{ $attributes->merge(['class' => 'impersonator-leave']) }}>{{ $label }}</a>
