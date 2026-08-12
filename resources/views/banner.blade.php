@php
    /**
     * The impersonation banner.
     *
     * An impersonated session that does not announce itself is how an operator
     * forgets which account they are in and takes an action as somebody else. The
     * banner is therefore on by default, and shows the mode: "you are read-only"
     * and "you can do anything" need to be distinguishable at a glance.
     *
     * Everything rendered here is escaped. The target's display name comes from a
     * user-editable attribute, so treating it as markup would make the banner an
     * XSS sink reachable by any user who can set their own name.
     */
    $session = $impersonation;
    $mode = $session->mode->name;
    $isReadOnly = $mode === 'read_only';
    $isFull = $mode === 'full';
@endphp

<div
    id="impersonator-banner"
    data-impersonator-theme="{{ $theme }}"
    data-impersonator-mode="{{ $mode }}"
    role="status"
    aria-live="polite"
>
    <div class="impersonator-banner__inner">
        <span class="impersonator-banner__badge" aria-hidden="true">
            @if ($isReadOnly) &#128065; @elseif ($isFull) &#9888; @else &#128274; @endif
        </span>

        <span class="impersonator-banner__text">
            Viewing as <strong>{{ $targetName }}</strong>
            @if ($impersonatorName)
                <span class="impersonator-banner__muted">&middot; signed in as {{ $impersonatorName }}</span>
            @endif
        </span>

        @if ($showMode)
            {{-- The label comes from the presenter, not from the raw config key. `data-` keeps the
                 untranslated value available for styling and for a host's own scripting. --}}
            <span class="impersonator-banner__mode" data-impersonator-mode="{{ $mode }}">{{ $modeName }}</span>
        @endif

        @if ($showDuration)
            <time
                class="impersonator-banner__muted"
                datetime="{{ $session->startedAt->format(DATE_ATOM) }}"
                title="Started {{ $session->startedAt->format('Y-m-d H:i:s T') }}"
            >since {{ $session->startedAt->format('H:i') }}</time>
        @endif

        @if ($expiresAt)
            {{-- `datetime` carries the machine-readable instant so a host application can
                 attach its own live countdown without re-deriving the deadline. --}}
            <time
                class="impersonator-banner__muted"
                datetime="{{ $expiresAt->format(DATE_ATOM) }}"
                title="Expires {{ $expiresAt->format('Y-m-d H:i:s T') }}"
                data-impersonator-expires-in="{{ $remainingSeconds }}"
            >expires {{ $expiresAt->format('H:i') }}</time>
        @endif

        @if ($canExtend)
            {{-- A form, not a link: extending changes state, so it must not be reachable by a
                 prefetch or a pasted URL. --}}
            <form class="impersonator-banner__extend-form" method="POST" action="{{ $extendUrl }}">
                @csrf
                <button type="submit" class="impersonator-banner__extend">Extend</button>
            </form>
        @elseif ($extendReason !== null && $expiresAt)
            {{-- Shown rather than hidden. An operator who cannot extend needs to know before
                 the session ends under them, not at the moment it does. --}}
            <span class="impersonator-banner__muted" title="{{ $extendReason }}">cannot extend</span>
        @endif

        <a class="impersonator-banner__leave" href="{{ $leaveUrl }}">Leave</a>
    </div>
</div>

<style>
    #impersonator-banner {
        --imp-bg: #1f2937;
        --imp-fg: #f9fafb;
        --imp-muted: #9ca3af;
        --imp-accent: #fbbf24;
        --imp-border: rgba(255, 255, 255, .14);

        position: fixed;
        {{ $position === 'top' ? 'top' : 'bottom' }}: 0;
        left: 0;
        right: 0;
        z-index: 2147483000;
        background: var(--imp-bg);
        color: var(--imp-fg);
        font: 500 13px/1.4 ui-sans-serif, system-ui, -apple-system, "Segoe UI", sans-serif;
        border-{{ $position === 'top' ? 'bottom' : 'top' }}: 1px solid var(--imp-border);
        box-shadow: 0 {{ $position === 'top' ? '2px' : '-2px' }} 12px rgba(0, 0, 0, .18);
    }

    #impersonator-banner[data-impersonator-mode="full"] { --imp-accent: #f87171; }
    #impersonator-banner[data-impersonator-mode="read_only"] { --imp-accent: #60a5fa; }

    #impersonator-banner[data-impersonator-theme="light"] {
        --imp-bg: #fffbeb;
        --imp-fg: #1f2937;
        --imp-muted: #6b7280;
        --imp-border: rgba(0, 0, 0, .12);
    }

    @if ($theme === 'auto')
        @media (prefers-color-scheme: light) {
            #impersonator-banner[data-impersonator-theme="auto"] {
                --imp-bg: #fffbeb;
                --imp-fg: #1f2937;
                --imp-muted: #6b7280;
                --imp-border: rgba(0, 0, 0, .12);
            }
        }
    @endif

    .impersonator-banner__inner {
        display: flex;
        align-items: center;
        gap: 10px;
        flex-wrap: wrap;
        max-width: 1400px;
        margin: 0 auto;
        padding: 8px 16px;
    }

    .impersonator-banner__text { flex: 1 1 auto; }
    .impersonator-banner__muted { color: var(--imp-muted); font-weight: 400; }

    .impersonator-banner__mode {
        text-transform: uppercase;
        letter-spacing: .06em;
        font-size: 10px;
        font-weight: 700;
        padding: 3px 7px;
        border-radius: 4px;
        color: var(--imp-bg);
        background: var(--imp-accent);
        white-space: nowrap;
    }

    .impersonator-banner__leave {
        color: var(--imp-fg);
        text-decoration: none;
        font-weight: 600;
        padding: 4px 12px;
        border: 1px solid var(--imp-border);
        border-radius: 5px;
        white-space: nowrap;
    }

    /* The extend control sits in a form, which is block by default and would otherwise
       break the banner's single flex row. */
    .impersonator-banner__extend-form {
        display: inline-flex;
        margin: 0;
    }

    .impersonator-banner__extend {
        font: inherit;
        color: var(--imp-fg);
        background: none;
        cursor: pointer;
        font-weight: 600;
        padding: 4px 12px;
        border: 1px solid var(--imp-border);
        border-radius: 5px;
        white-space: nowrap;
    }

    .impersonator-banner__extend:hover,
    .impersonator-banner__extend:focus-visible,
    .impersonator-banner__leave:hover,
    .impersonator-banner__leave:focus-visible {
        background: var(--imp-accent);
        color: var(--imp-bg);
        border-color: transparent;
    }

    @media (prefers-reduced-motion: no-preference) {
        .impersonator-banner__extend,
        .impersonator-banner__leave { transition: background .12s ease, color .12s ease; }
    }
</style>
