# Add an impersonate button

Put a button on a user row and a banner in your layout.

```blade
{{-- resources/views/admin/users/index.blade.php --}}
@foreach ($users as $user)
    <tr>
        <td>{{ $user->name }}</td>
        <td><x-impersonate-button :user="$user" /></td>
    </tr>
@endforeach
```

```blade
{{-- resources/views/layouts/app.blade.php --}}
<body>
    <x-impersonation-banner />
    @yield('content')
</body>
```

Neither needs a conditional. The button renders nothing when the current operator may not
impersonate that account, and the banner renders nothing when nobody is impersonating — so a
forgotten `@if` cannot expose a button or hide a banner.

Reference: [Blade components](../tools/blade-components.md).

---

[← Docs index](../../README.md#documentation)
