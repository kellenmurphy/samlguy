<script lang="ts">
    import { FIELD_EXPLANATIONS } from '$lib/explanations';

    let { key }: { key: string | undefined } = $props();

    const text = key ? FIELD_EXPLANATIONS[key] : undefined;

    let visible = $state(false);
    let tipX = $state(0);
    let tipY = $state(0);

    function show(e: Event) {
        const rect = (e.currentTarget as HTMLElement).getBoundingClientRect();
        tipX = rect.left + rect.width / 2;
        tipY = rect.top;
        visible = true;
    }

    function hide() {
        visible = false;
    }
</script>

{#if text}
    <button
        type="button"
        class="ml-1 inline-flex h-3.5 w-3.5 shrink-0 cursor-help items-center justify-center rounded-full border-0 bg-neutral-200 p-0 text-[10px] font-bold leading-none text-neutral-500 select-none outline-none focus-visible:ring-1 focus-visible:ring-neutral-400 dark:bg-neutral-700 dark:text-neutral-400 dark:focus-visible:ring-neutral-500"
        aria-label={text}
        onmouseenter={show}
        onfocus={show}
        onmouseleave={hide}
        onblur={hide}
    >?</button>
    {#if visible}
        <div
            role="tooltip"
            class="pointer-events-none z-[9999] w-72 rounded-md bg-neutral-900 px-3 py-2 text-xs font-normal normal-case leading-relaxed tracking-normal text-neutral-100 shadow-lg dark:bg-neutral-100 dark:text-neutral-900"
            style="position: fixed; left: {tipX}px; top: {tipY}px; transform: translate(-50%, calc(-100% - 8px));"
        >
            {text}
        </div>
    {/if}
{/if}
