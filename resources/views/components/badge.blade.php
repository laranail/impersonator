{{-- Compact mode indicator, for placing next to the action it constrains. --}}
<span {{ $attributes->merge(['class' => 'impersonator-badge']) }}
      data-impersonator-mode="{{ $mode }}"
      @if ($description) title="{{ $description }}" @endif>
    {{ str_replace('_', ' ', $mode) }}@if ($targetName) · {{ $targetName }}@endif
</span>

<style>
    .impersonator-badge {
        display: inline-block;
        font: 700 10px/1.4 ui-sans-serif, system-ui, sans-serif;
        text-transform: uppercase;
        letter-spacing: .06em;
        padding: 3px 7px;
        border-radius: 4px;
        color: #1f2937;
        background: #fbbf24;
        white-space: nowrap;
    }

    .impersonator-badge[data-impersonator-mode="full"] { background: #f87171; color: #fff; }
    .impersonator-badge[data-impersonator-mode="read_only"] { background: #60a5fa; color: #fff; }
</style>
